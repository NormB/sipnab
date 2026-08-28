// SPDX-License-Identifier: MIT OR Apache-2.0

//! Guards documentation against drift: every `--flag` README.md advertises
//! must actually exist in the CLI (clap) definition.
//!
//! Regression context: README once listed `--codec-asym`, `--ptime-asym`,
//! `--payload-asym`, `--duration-asym`, and `--late-media` as standalone
//! flags, but they are `--filter` DSL aliases only.
//!
//! Beyond flag drift, this crate also pins other doc-vs-reality contracts:
//! `--mcp` examples must pass `-N`/`--no-tui`, the Code of Conduct must keep
//! a working enforcement contact, the man page must match the crate version
//! and license, "current version" markers in install/benchmark docs must
//! match Cargo.toml, and the benchmark tables must stay identical between
//! the wiki source and the website copy. Gated on the `native` feature
//! because it introspects the real clap `Cli`.
#![cfg(feature = "native")]

use clap::CommandFactory;
use std::collections::BTreeSet;

#[path = "support/markdown.rs"]
mod markdown;

/// Long flags mentioned in the docs that belong to OTHER tools (cargo, docker,
/// apt, editcap, systemctl, voipmonitor, `claude mcp add`), not to sipnab —
/// each scoped to the exact doc label(s) where it legitimately appears.
///
/// Scoping (rather than a flat global allowlist) keeps a foreign name from
/// masking a real sipnab-flag typo in an unrelated doc: e.g. `--target` is a
/// cargo/xcode flag excused only in the build/install docs, so a stray
/// `--target` written as if it were a sipnab flag in `docs/cli-reference.md`
/// would still fail this guard instead of being silently whitelisted. The
/// label is the first element of each `docs` tuple in `readme_long_flags_exist_in_cli`.
const FOREIGN_FLAGS: &[(&str, &[&str])] = &[
    // `--git` is cargo's. The build-and-release page carries the
    // `cargo install --git ... --tag` line the site-build gate prints when zola
    // is missing, because Zola publishes no aarch64 Linux binary and building
    // one is the only way to get it on such a machine.
    (
        "git",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    // `--audio` belongs to `harness/clients/vcon_view.py`, the small reader the
    // capture-stack page uses to extract a stored container's WAV. It is a
    // harness client rather than sipnab, and naming it here is what keeps this
    // gate from reading every tool a page demonstrates as sipnab's own.
    (
        "audio",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
        ],
    ),
    // rtpengine's own flags. The capture-stack page shows how to start the
    // relay, and a media relay is not sipnab -- `--interface`, `--listen-ng`
    // and the port range are its command line, and `--homer*` is how it
    // mirrors the ng control plane where a separate sipnab can read it.
    // Scoped to the one page that stands the relay up.
    (
        "interface",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
        ],
    ),
    (
        "listen-ng",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
        ],
    ),
    (
        "port-min",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
        ],
    ),
    (
        "port-max",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
        ],
    ),
    (
        "homer",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
        ],
    ),
    (
        "homer-protocol",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
        ],
    ),
    (
        "homer-enable-ng",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
        ],
    ),
    // `--data-binary` is curl's. The cookbook and the vCon page pipe a
    // container straight into a conserver, and `--data-binary @-` is what
    // makes that a single runnable line rather than a file dance. Scoped to
    // the pages that show the POST.
    (
        "data-binary",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
            "docs/examples.md",
            "website/content/docs/cookbook.md",
        ],
    ),
    // `--example` is cargo's. The vCon page points at the committed
    // `export_vcon` example because a program that compiles with the tree
    // cannot drift from the API the way a fragment on a page can.
    ("example", &["docs/vcon.md", "website/content/docs/vcon.md"]),
    // `--keylogfile` is eCapture's, not sipnab's, and BOTH pages that name it
    // are legitimate: the cookbook's §7e tells the reader to run
    // `ecapture tls -m keylog --keylogfile=...` on the SIP host to lift secrets
    // out of a daemon that cannot be restarted, and the CLI reference names it
    // so the `--keylog-fd` example is a runnable whole. Scoped to those four
    // files: written anywhere else it would read as a sipnab flag and must
    // still fail this guard.
    // `--features` is cargo's, not sipnab's. The CLI reference names it because
    // the `bpf` backend needs a build that carries it, and a reader told to use
    // `--uprobe-backend bpf` has to know what produces such a binary. Scoped to
    // the two CLI pages: written anywhere else it would read as a sipnab flag
    // and must still fail this guard.
    (
        "features",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
            "docs/uprobe-walkthrough.md",
            "website/content/docs/uprobe-walkthrough.md",
            "docs/cli-reference.md",
            "website/content/docs/cli.md",
            // The plugins page tells a reader to BUILD a plugin, so the whole
            // cargo invocation has to be runnable as written.
            "docs/plugins.md",
            "website/content/docs/plugins.md",
            // The troubleshooting page answers "sipnab refuses --export-vcon"
            // with the cargo line that produces a binary carrying it. A remedy
            // a reader cannot run is not a remedy.
            "docs/troubleshooting.md",
            "website/content/docs/troubleshooting.md",
            // The TLS chooser names `--features bpf` because method 4 needs a
            // build that carries it, exactly as the CLI reference does.
            "docs/tls-capture.md",
            "website/content/docs/tls-capture.md",
            // The library page's worked-examples section gives the cargo
            // invocations that RUN examples/*.rs. A library consumer builds
            // against this crate, so `--features native` is the one thing
            // between them and a compile error.
            "docs/library.md",
            // `vcon` is NON-DEFAULT, so a reader following the walkthrough has
            // no export at all without naming it. The whole point of the page
            // is a runnable sequence, and a stock binary silently lacking the
            // flag is the first thing that would stop them.
            "docs/vcon.md",
            "website/content/docs/vcon.md",
        ],
    ),
    // `--homer` and `--homer-enable-ng` are RTPENGINE's, named on the pages
    // that tell an operator how to configure a relay. They have to be written
    // as flags because the reader types them into rtpengine's config, and they
    // must never be mistaken for sipnab's own -- scoped to those four pages
    // (two sources and their generated mirrors), so the same spelling anywhere
    // else still fails this guard.
    (
        "homer",
        &[
            "docs/rtpengine.md",
            "website/content/docs/rtpengine.md",
            "docs/internals/rtpengine-control-plane.md",
            "website/content/docs/internals/rtpengine-control-plane.md",
        ],
    ),
    (
        "homer-enable-ng",
        &[
            "docs/rtpengine.md",
            "website/content/docs/rtpengine.md",
            "docs/internals/rtpengine-control-plane.md",
            "website/content/docs/internals/rtpengine-control-plane.md",
        ],
    ),
    // `--interface` is RTPENGINE's too, and the control-plane page has to name
    // it exactly: rtpengine allocates from ONE port range across every
    // `--interface`, which is the whole reason sipnab keys a relay-side socket
    // on address AND port. Keyed on the port alone, one interface's media gets
    // attributed to the other interface's call. Writing it without the dashes
    // would satisfy this guard and lose the fact that it is a real flag a
    // reader can go and look up. Scoped to that page and its generated mirror,
    // so the same spelling anywhere else still fails.
    (
        "interface",
        &[
            "docs/internals/rtpengine-control-plane.md",
            "website/content/docs/internals/rtpengine-control-plane.md",
        ],
    ),
    // `--now` is systemd's, on `systemctl enable --now`. The cookbook's
    // "Run sipnab as a service" recipe gives a unit file and then the two
    // commands that install it, and `enable` without `--now` leaves the
    // service configured but not started -- which is precisely the outcome a
    // reader following a "run it as a service" recipe would report as broken.
    // Scoped to the cookbook and its generated mirror: written anywhere else
    // it would read as a sipnab flag and must still fail this guard.
    (
        "now",
        &["docs/examples.md", "website/content/docs/cookbook.md"],
    ),
    // `--example` is cargo's, on `cargo run --example <name>`. It appears
    // only on the library page, which is the one page whose runnable
    // commands target `examples/*.rs` rather than the `sipnab` binary.
    // Scoped there: written anywhere else it would read as a sipnab flag
    // and must still fail this guard.
    ("example", &["docs/library.md"]),
    // `--undefined-only` is binutils `nm`, and `--keylogfile` is eCapture's.
    // The TLS chooser names both because the commands it gives have to be
    // runnable as written: one finds which symbol a daemon actually calls,
    // the other lifts keys from a daemon nobody can restart.
    (
        "undefined-only",
        &["docs/tls-capture.md", "website/content/docs/tls-capture.md"],
    ),
    // `--libssl` and `--pid` are eCapture's. The TLS chooser names both because
    // getting them wrong is the commonest way a keylog comes back empty:
    // eCapture picks the TLS library to instrument by looking at curl, which
    // need not be the one the SIP daemon maps, and `--pid` pins it to a single
    // process while a forking daemon spreads connections across all its
    // workers. Scoped to the two TLS pages, as the others here are.
    (
        "libssl",
        &["docs/tls-capture.md", "website/content/docs/tls-capture.md"],
    ),
    (
        "pid",
        &["docs/tls-capture.md", "website/content/docs/tls-capture.md"],
    ),
    (
        "keylogfile",
        &["docs/tls-capture.md", "website/content/docs/tls-capture.md"],
    ),
    // `--release` and `--target` are cargo's too, and appear for the same
    // reason: `cargo build --release --target wasm32-unknown-unknown` is what
    // produces a loadable plugin, and a half-quoted command is not runnable.
    (
        "release",
        &[
            "docs/vcon-harness.md",
            "website/content/docs/vcon-harness.md",
            "docs/plugins.md",
            "website/content/docs/plugins.md",
            // The vCon walkthrough builds a release binary because the export
            // runs over a capture, and a debug build is slow enough on a real
            // one to read as a hang.
            "docs/vcon.md",
            "website/content/docs/vcon.md",
            // The troubleshooting page answers "sipnab refuses --export-vcon"
            // with the same cargo line, for the same reason.
            "docs/troubleshooting.md",
            "website/content/docs/troubleshooting.md",
        ],
    ),
    (
        "target",
        &["docs/plugins.md", "website/content/docs/plugins.md"],
    ),
    // `--undefined-only` is binutils' `nm`, not sipnab's. The cookbook names it
    // because a reader whose daemon calls `SSL_write_ex` rather than
    // `SSL_write` needs a way to find that out before choosing
    // `--uprobe-symbol`. Scoped to the cookbook and its mirror.
    (
        "undefined-only",
        &[
            "docs/uprobe-walkthrough.md",
            "website/content/docs/uprobe-walkthrough.md",
            "docs/examples.md",
            "website/content/docs/cookbook.md",
        ],
    ),
    (
        "keylogfile",
        &[
            "docs/examples.md",
            "website/content/docs/cookbook.md",
            "docs/cli-reference.md",
            "website/content/docs/cli.md",
        ],
    ),
    // `demos/gen-mcp-examples.sh --check` re-runs the homepage's four MCP
    // examples and fails on any difference. It is that script's flag, not
    // sipnab's, and the testing page names it because a reader who has just
    // been told the examples are gated needs to know what runs the gate.
    // Scoped to that page alone: a bare `--check` written as a sipnab flag
    // anywhere else must still fail this guard.
    (
        "check",
        &[
            "docs/internals/testing.md",
            "website/content/docs/internals/testing.md",
        ],
    ),
    // `perf` and `cargo` flags in the profiling recipes. None of these is a
    // sipnab flag; they belong to the tools the page tells you to run.
    (
        "call-graph",
        &[
            "docs/internals/profiling.md",
            "website/content/docs/internals/profiling.md",
        ],
    ),
    (
        "features",
        &[
            "docs/internals/profiling.md",
            "website/content/docs/internals/profiling.md",
        ],
    ),
    (
        "no-children",
        &[
            "docs/internals/profiling.md",
            "website/content/docs/internals/profiling.md",
        ],
    ),
    (
        "profile",
        &[
            "docs/internals/profiling.md",
            "website/content/docs/internals/profiling.md",
        ],
    ),
    (
        "runs",
        &[
            "docs/internals/profiling.md",
            "website/content/docs/internals/profiling.md",
        ],
    ),
    (
        "sort",
        &[
            "docs/internals/profiling.md",
            "website/content/docs/internals/profiling.md",
        ],
    ),
    (
        "stdio",
        &[
            "docs/internals/profiling.md",
            "website/content/docs/internals/profiling.md",
        ],
    ),
    // `rustc --print deployment-target`, in the macOS floor recipe. The floors
    // are the compiler's defaults, so the compiler is what the doc tells the
    // reader to ask — a copy of the number would be the thing this avoids.
    (
        "print",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    // cargo / cross / xcode-select build & install recipes
    (
        "release",
        &[
            "README.md",
            "docs/install.md",
            "website/content/docs/install.md",
            "docs/mcp.md",
            "docs/rest-api.md",
            "website/content/docs/cookbook.md",
            "website/content/docs/api.md",
            "website/content/docs/build.md",
            "docs/examples.md",
            "website/content/docs/mcp.md",
        ],
    ),
    (
        "target",
        &[
            "README.md",
            "docs/install.md",
            "website/content/docs/install.md",
            "website/content/docs/build.md",
        ],
    ),
    // `cargo install --path <dir> --bin sipnab`, in the source-install recipe.
    // --bin is load-bearing there, not decoration: without it cargo installs
    // every [[bin]] whose required-features are met, and gen_fixture's are.
    (
        "path",
        &[
            "docs/install.md",
            "website/content/docs/install.md",
            "website/content/docs/build.md",
        ],
    ),
    (
        "bin",
        &[
            "docs/install.md",
            "website/content/docs/install.md",
            "website/content/docs/build.md",
        ],
    ),
    // `rustc --cfg sipnab_tsan`, in the ThreadSanitizer section: the flag that
    // drops mimalloc for the sanitizer build. A rustc flag, not a sipnab one.
    (
        "cfg",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    // `sha256sum --ignore-missing` and `gh attestation verify --repo`, in the
    // download-verification recipes.
    (
        "ignore-missing",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    (
        "repo",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    // Alpine's package manager, in the musl/Alpine build recipes.
    ("no-cache", &["website/content/docs/build.md"]),
    // contrib/mcp/trace-call.py's own flags, in the "Drive it from a script"
    // section. That script is an MCP *client*: it never launches sipnab, so
    // these are argparse options belonging to the example, not sipnab's CLI.
    // Scoped to the two mcp-deploy surfaces so the same names anywhere
    // else still fail the gate.
    (
        "node",
        &["docs/mcp-deploy.md", "website/content/docs/mcp-deploy.md"],
    ),
    (
        "call-id",
        &["docs/mcp-deploy.md", "website/content/docs/mcp-deploy.md"],
    ),
    (
        "token-file",
        &["docs/mcp-deploy.md", "website/content/docs/mcp-deploy.md"],
    ),
    // bench/carrier.py and bench/scaling.sh flags, in the reproduce recipes.
    // These belong to the benchmark harness, not to sipnab's CLI.
    //
    // `--calls` and `--out` reach `internals/profiling.md` as well, which
    // gained the recipe for cutting one generated corpus into the rotated
    // members a MULTI-FILE `-I` needs — a different reader path from a single
    // file, and one no other page tells you how to measure. The page already
    // excuses `--runs` from the same harness.
    (
        "calls",
        &[
            "docs/benchmarks.md",
            "website/content/docs/benchmarks.md",
            "docs/internals/profiling.md",
            "website/content/docs/internals/profiling.md",
        ],
    ),
    (
        "out",
        &[
            "docs/benchmarks.md",
            "website/content/docs/benchmarks.md",
            "docs/internals/profiling.md",
            "website/content/docs/internals/profiling.md",
        ],
    ),
    (
        "call-ids",
        &["docs/benchmarks.md", "website/content/docs/benchmarks.md"],
    ),
    (
        "stream-pairs",
        &["docs/benchmarks.md", "website/content/docs/benchmarks.md"],
    ),
    (
        "runs",
        &["docs/benchmarks.md", "website/content/docs/benchmarks.md"],
    ),
    (
        "features",
        &[
            "README.md",
            "docs/install.md",
            "docs/mcp.md",
            "docs/rest-api.md",
            "website/content/docs/cookbook.md",
            "website/content/docs/install.md",
            "website/content/docs/api.md",
            "website/content/docs/build.md",
            "website/content/docs/_index.md",
            "docs/examples.md",
            "website/content/docs/mcp.md",
            "docs/mcp-deploy.md",
            "website/content/docs/mcp-deploy.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "no-default-features",
        &[
            "README.md",
            "docs/install.md",
            "website/content/docs/install.md",
            "docs/mcp.md",
            "website/content/docs/cookbook.md",
            "website/content/docs/build.md",
            "docs/examples.md",
            "website/content/docs/mcp.md",
            "CONTRIBUTING.md",
        ],
    ),
    // useradd / systemctl / certbot / claude-cli, in the deployment scenarios
    // of the MCP walkthrough. That page was outside the old hand list entirely,
    // which is how it could have advertised a renamed --mcp-* flag on both the
    // wiki and the site with this suite green.
    (
        "system",
        &["docs/mcp-deploy.md", "website/content/docs/mcp-deploy.md"],
    ),
    (
        "home",
        &["docs/mcp-deploy.md", "website/content/docs/mcp-deploy.md"],
    ),
    (
        "shell",
        &["docs/mcp-deploy.md", "website/content/docs/mcp-deploy.md"],
    ),
    (
        "no-pager",
        &["docs/mcp-deploy.md", "website/content/docs/mcp-deploy.md"],
    ),
    (
        "nginx",
        &["docs/mcp-estate.md", "website/content/docs/mcp-estate.md"],
    ),
    (
        "allowedTools",
        &["docs/mcp-deploy.md", "website/content/docs/mcp-deploy.md"],
    ),
    // The benchmark harness flags were excused for docs/benchmarks.md but not
    // for its hand-maintained site twin, which is deliberately not generated.
    // Developer-tree tool flags: cargo, npm, git, insta and the `--your-flag`
    // placeholder in the "add a CLI flag" walkthrough. docs/internals/ is in the
    // corpus because it is published (wiki + site nav), so a phantom sipnab flag
    // there is a real defect; these belong to other tools and are excused per page.
    (
        "accept",
        &[
            "docs/internals/testing.md",
            "docs/internals/tui-testing.md",
            "website/content/docs/internals/testing.md",
            "website/content/docs/internals/tui-testing.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "all-features",
        &[
            "docs/internals/README.md",
            "docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "website/content/docs/internals/_index.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/testing.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "all-targets",
        &[
            "docs/internals/README.md",
            "docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "website/content/docs/internals/_index.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/testing.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "bin",
        &[
            "docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/testing.md",
        ],
    ),
    (
        "calls",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "check",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "features",
        &[
            "docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "docs/internals/tui-testing.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/testing.md",
            "website/content/docs/internals/tui-testing.md",
        ],
    ),
    (
        "flag",
        &[
            "docs/internals/testing.md",
            "website/content/docs/internals/testing.md",
        ],
    ),
    (
        "ignored",
        &[
            "docs/internals/build-ci-release.md",
            "docs/internals/tui-testing.md",
            "website/content/docs/internals/build-ci-release.md",
            "website/content/docs/internals/tui-testing.md",
        ],
    ),
    (
        "install-",
        &[
            "docs/internals/README.md",
            "website/content/docs/internals/_index.md",
        ],
    ),
    (
        "no-default-features",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "no-deps",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "out",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "package",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "path",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "profile",
        &[
            "docs/internals/testing.md",
            "website/content/docs/internals/testing.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "repo",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "runs",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    (
        "test",
        &[
            "docs/internals/testing.md",
            "docs/internals/tui-testing.md",
            "website/content/docs/internals/testing.md",
            "website/content/docs/internals/tui-testing.md",
            // The vCon page names the test binary that proves the export, so a
            // reader can run the same check the repository runs rather than
            // taking the page's word for it.
            "docs/vcon.md",
            "website/content/docs/vcon.md",
        ],
    ),
    (
        "tests",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
            // CONTRIBUTING's pre-push table quotes the feature-matrix gate,
            // whose whole point is the `--tests` cargo flag: without it the
            // matrix compiles no test file and passes over nothing.
            "CONTRIBUTING.md",
        ],
    ),
    (
        // Cargo's flag, not sipnab's. Every page here documents the clippy
        // command the hooks and CI run, which carries `--workspace` because
        // without it the lint stops at the main crate and the other workspace
        // members go unlinted.
        "workspace",
        &[
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
            "docs/internals/testing.md",
            "website/content/docs/internals/testing.md",
            "docs/internals/README.md",
            "website/content/docs/internals/_index.md",
            "CONTRIBUTING.md",
        ],
    ),
    (
        "your-flag",
        &[
            "docs/internals/walkthroughs.md",
            "website/content/docs/internals/walkthroughs.md",
        ],
    ),
    // `cargo fmt --all -- --check`, the hook gate. Named in CONTRIBUTING's hook
    // tables and, since the check moved into pre-commit as gate 0, in the
    // build-and-CI internals page that enumerates those gates.
    (
        "all",
        &[
            "CONTRIBUTING.md",
            "docs/internals/build-ci-release.md",
            "website/content/docs/internals/build-ci-release.md",
        ],
    ),
    ("install", &["README.md", "CONTRIBUTING.md"]),
    // docker run flags (install docs)
    (
        "net",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    (
        "rm",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    // apt (noaudio .deb guidance)
    (
        "no-install-recommends",
        &["docs/install.md", "website/content/docs/install.md"],
    ),
    // editcap (`--strip-secrets` is sipnab's analog)
    (
        "discard-all-secrets",
        &["docs/cli-reference.md", "website/content/docs/cli.md"],
    ),
    // systemctl (mcp service management)
    (
        "now",
        &[
            "docs/mcp-deploy.md",
            "website/content/docs/mcp-deploy.md",
            "docs/mcp-estate.md",
            "website/content/docs/mcp-estate.md",
        ],
    ),
    // claude mcp add (http-transport client wiring)
    (
        "transport",
        &[
            "docs/mcp-deploy.md",
            "website/content/docs/mcp-deploy.md",
            "docs/mcp-estate.md",
            "website/content/docs/mcp-estate.md",
        ],
    ),
    (
        "header",
        &[
            "docs/mcp-deploy.md",
            "website/content/docs/mcp-deploy.md",
            "docs/mcp-estate.md",
            "website/content/docs/mcp-estate.md",
        ],
    ),
];

/// True when `flag` is a known foreign-tool flag excused in `doc` specifically.
/// A foreign flag mentioned in a doc outside its scope is NOT excused, so it
/// surfaces as drift.
fn is_foreign_flag(flag: &str, doc: &str) -> bool {
    FOREIGN_FLAGS
        .iter()
        .any(|(name, docs)| *name == flag && docs.contains(&doc))
}

/// All long flag names (including aliases) the real CLI accepts.
///
/// # Returns
/// The set of long option names, plus the implicit `help`/`version`.
fn cli_long_flags() -> BTreeSet<String> {
    let cmd = sipnab::cli::Cli::command();
    let mut flags = BTreeSet::new();

    // Flags that exist only under a non-default Cargo feature.
    //
    // This enumerates the CLI clap actually built, so a `#[cfg(feature = ...)]`
    // flag is absent whenever the suite runs without that feature — and the
    // docs, which describe the whole program, still name it. The reduced-feature
    // CI matrix hits exactly that: `--plugin` is real under `plugins` and
    // invisible under `native,hep,api,mcp,mcp-http`, so the gate reported the
    // documentation as advertising a flag that does not exist.
    //
    // Listed rather than inferred, so adding a feature-gated flag is a
    // deliberate entry here and not something a reader has to discover from a
    // red matrix job. Each name must still be documented like any other flag.
    const FEATURE_GATED: &[&str] = &["plugin"];
    for f in FEATURE_GATED {
        flags.insert((*f).to_string());
    }

    for arg in cmd.get_arguments() {
        if let Some(long) = arg.get_long() {
            flags.insert(long.to_string());
        }
        if let Some(aliases) = arg.get_all_aliases() {
            for alias in aliases {
                flags.insert(alias.to_string());
            }
        }
    }
    // clap provides these automatically; get_arguments() doesn't list them.
    flags.insert("help".to_string());
    flags.insert("version".to_string());
    flags
}

/// Extract `--flag-name` tokens from markdown. Requires a letter after the
/// dashes so table rules (`|----|`) and `--` used as an em-dash don't match.
///
/// # Returns
/// The distinct flag names found, without the leading dashes.
fn extract_long_flags(text: &str) -> BTreeSet<String> {
    // Strip markdown link targets first. GitHub-style heading anchors embed a
    // double hyphen wherever the heading had an em dash, so
    // `](#scenario-5--a-fleet-of-capture-hosts)` otherwise reads as a flag
    // named `--a-fleet-of-capture-hosts`. One page carries 19 of them.
    static LINK: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let link = LINK.get_or_init(|| regex::Regex::new(r"\]\([^)]*\)").unwrap());
    let text = link.replace_all(text, "]");

    let re = regex::Regex::new(r"--([A-Za-z][A-Za-z0-9-]*)").unwrap();
    re.captures_iter(&text).map(|c| c[1].to_string()).collect()
}

/// Every published markdown page, as `(repo-relative path, contents)`.
///
/// The published surface is everything a reader can reach: the repository root
/// pages, all of `docs/` including `docs/internals/`, and the Zola content
/// tree. Only the planning trees are excluded, for the same reason
/// `link_integrity_test` excludes them — they are a historical record, not
/// documentation anyone is pointed at, and editing them to satisfy a gate
/// corrupts them.
///
/// `docs/internals/` is in scope because it is PUBLISHED: `build-wiki.py` maps
/// all ten pages to `Internals-*` wiki pages and the site nav links the
/// mirrors. An earlier version of this excluded it, with a comment claiming it
/// was covered because "its own drift gates live in dev_docs_drift_test" —
/// true for links, symbols and mermaid, and false for flags, which that file
/// never checks. A phantom flag added there passed 82 tests while live on two
/// published pages.
fn published_markdown() -> Vec<(String, String)> {
    // Root pages a reader reaches. CONTRIBUTING.md is in: a phantom sipnab
    // flag there misleads a contributor, which is a real reader.
    //
    // Two root pages stay out, on principle rather than convenience:
    //   CHANGELOG.md — a historical record. An entry naming a flag that has
    //     since been renamed or removed is CORRECT, and gating it against the
    //     current CLI would force the history to be rewritten to stay green.
    //   THIRD-PARTY-NOTICES.md — generated from the dependency tree; its
    //     content is not authored here.
    const ROOT_PAGES: &[&str] = &["README.md", "SECURITY.md", "CONTRIBUTING.md"];
    const SKIP: &[&str] = &["docs/design/", "docs/research/", "docs/superpowers/"];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .args(["ls-files", "*.md"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(out.status.success(), "git ls-files failed");
    let mut pages: Vec<(String, String)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|rel| {
            if SKIP.iter().any(|d| rel.starts_with(d)) {
                return false;
            }
            let in_docs = rel.starts_with("docs/");
            in_docs || rel.starts_with("website/content/") || ROOT_PAGES.contains(rel)
        })
        .filter_map(|rel| {
            std::fs::read_to_string(root.join(rel))
                .ok()
                .map(|t| (rel.to_string(), t))
        })
        .collect();
    assert!(
        pages.len() >= 55,
        "only {} published markdown pages found — the derivation is reading \
         almost nothing and every gate built on it passes vacuously",
        pages.len()
    );
    pages.sort();
    pages
}

/// Every `--flag` mentioned across the user-facing docs exists in the clap
/// CLI (or is a whitelisted foreign-tool flag); extraction is self-checked.
#[test]
fn readme_long_flags_exist_in_cli() {
    // Derived from the tree, not hand-listed. The old list held 34
    // include_str! entries and missed three published pages:
    // docs/mcp-deploy.md carried 21 long-flag tokens and is rendered on
    // both the wiki and the site, so a renamed --mcp-* flag could ship live on
    // two surfaces with this suite green. Demonstrated: a phantom flag added
    // there passed 85 tests, while the same string in a listed page failed.
    //
    // include_str! bought a build error when a listed file was deleted. A
    // derived list is strictly better for that purpose: a renamed file is
    // still scanned under its new name, where before it silently left the
    // corpus.
    let corpus = published_markdown();
    let docs: Vec<(&str, &str)> = corpus
        .iter()
        .map(|(label, text)| (label.as_str(), text.as_str()))
        .collect();
    let docs = &docs[..];

    let known = cli_long_flags();
    let mut all_mentioned = BTreeSet::new();
    let mut failures = Vec::new();
    for (name, text) in docs {
        let mentioned = extract_long_flags(text);
        let phantom: Vec<&String> = mentioned
            .iter()
            .filter(|f| !known.contains(*f) && !is_foreign_flag(f, name))
            .collect();
        if !phantom.is_empty() {
            failures.push(format!("{name}: {phantom:?}"));
        }
        all_mentioned.extend(mentioned);
    }

    // Sanity: extraction must find known-good flags, so this test can never
    // pass vacuously on a broken regex or empty docs.
    assert!(
        all_mentioned.contains("problems") && all_mentioned.contains("from"),
        "flag extraction is broken: expected to find --problems and --from"
    );

    assert!(
        failures.is_empty(),
        "docs advertise flags that do not exist in src/cli.rs:\n  {}\n\
         If a name is a --filter DSL alias, document it as `--filter <alias>`, \
         not as a standalone flag. If it belongs to a foreign tool (cargo etc.), \
         add it to FOREIGN_FLAGS in tests/docs_drift_test.rs, scoped to this doc's label.",
        failures.join("\n  ")
    );
}

/// README keeps the libasound runtime note and a --no-default-features headless recipe.
#[test]
fn readme_documents_audio_runtime_dependency_and_headless_recipe() {
    // The `audio` default feature needs libasound at runtime; README must
    // keep saying so AND keep showing a no-audio recipe for headless hosts
    // (same warning build.rs emits — keep the two in sync).
    let readme = include_str!("../README.md");
    assert!(
        readme.contains("libasound"),
        "README must document the libasound runtime dependency of the audio feature"
    );
    assert!(
        readme.contains("--no-default-features"),
        "README must show a --no-default-features recipe to drop the audio feature"
    );
}

/// The flag extractor skips table rules and spaced dashes but still flags `---triple` typos.
#[test]
fn extraction_ignores_table_rules_and_em_dashes() {
    let md = "| a |\n|----|\n**Bold** -- prose with -- dashes\n`--real-flag` and ---triple";
    let got = extract_long_flags(md);
    assert_eq!(
        got,
        BTreeSet::from(["real-flag".to_string(), "triple".to_string()]),
        "extractor must skip table rules and spaced em-dashes (`---triple` \
         intentionally matches: a doc typo like `---flag` should be flagged, \
         and `triple` won't be a known flag)"
    );
}

/// Split a markdown document into its fenced code blocks (``` ... ```).
///
/// # Returns
/// The body text of each fenced block, in document order.
fn fenced_blocks(md: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in md.lines() {
        if line.trim_start().starts_with("```") {
            match current.take() {
                Some(done) => blocks.push(done),
                None => current = Some(String::new()),
            }
            continue;
        }
        if let Some(buf) = current.as_mut() {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    blocks
}

/// Regression guard: every documented `--mcp` invocation once omitted the
/// mandatory `-N`/`--no-tui`, so copy-pasting ANY example hit a hard CLI
/// error ("--mcp implies non-interactive mode"). Any fenced example that
/// starts sipnab with `--mcp` must also pass `-N` or `--no-tui`.
///
/// Covers both the wiki-source docs (`docs/`) and the published website
/// (`website/content/docs/`) — the website's mcp.md carries its own copy of
/// these examples, so a broken example there must fail this test too.
#[test]
fn mcp_examples_always_pass_no_tui() {
    let mut offenders = Vec::new();
    let doc_dirs = ["docs", "website/content/docs"];
    let entries = doc_dirs.iter().flat_map(|dir| {
        std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read doc dir {dir}: {e}"))
            .map(|entry| entry.expect("dir entry").path())
    });
    for path in entries {
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let md = std::fs::read_to_string(&path).expect("read doc");
        for block in fenced_blocks(&md) {
            // Join backslash continuations so a multi-line command is
            // checked as one logical invocation.
            let mut logical: Vec<String> = Vec::new();
            let mut cont = String::new();
            for line in block.lines() {
                if let Some(head) = line.trim_end().strip_suffix('\\') {
                    cont.push_str(head);
                    cont.push(' ');
                    continue;
                }
                cont.push_str(line);
                logical.push(std::mem::take(&mut cont));
            }
            for line in logical {
                // A bare `--mcp` (not an `--mcp-*` option like
                // --mcp-transport).
                let has_bare_mcp = line
                    .match_indices("--mcp")
                    .any(|(i, _)| !matches!(line.as_bytes().get(i + 5), Some(b'-')));
                // No "sipnab" requirement: client-config lines like
                // `"args": ["--mcp", ...]` name the binary elsewhere.
                if has_bare_mcp && !(line.contains("-N") || line.contains("--no-tui")) {
                    offenders.push(format!("{}: {}", path.display(), line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "--mcp examples missing -N/--no-tui (copy-paste would fail):\n{}",
        offenders.join("\n---\n")
    );
}

/// The security policy must keep a reachable disclosure address.
///
/// The Code of Conduct has been guarded this way since its enforcement contact
/// was once deleted outright. SECURITY.md carries the more consequential
/// address of the two — it is where an unreported vulnerability goes — and had
/// no such guard, so the same edit that broke the CoC would have gone unnoticed
/// here. It also promises response times, which are worthless if the address
/// they attach to has quietly vanished.
#[test]
fn security_policy_has_a_reporting_contact() {
    let sec = std::fs::read_to_string("SECURITY.md").expect("SECURITY.md");

    let email = regex::Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap();
    let found = email.find(&sec).map(|m| m.as_str().to_string());
    assert!(
        found.is_some(),
        "SECURITY.md names no email address — a vulnerability reporter has \
         nowhere to send a report, and the response-time table below promises \
         a reply to an address that does not exist"
    );

    assert!(
        !sec.to_ascii_uppercase().contains("[INSERT") && !sec.contains("TODO"),
        "SECURITY.md still carries a placeholder instead of a real contact"
    );

    // The instruction not to file publicly is the whole point of the private
    // channel; losing it sends reports to the issue tracker.
    assert!(
        sec.to_ascii_lowercase()
            .contains("do not open a public issue"),
        "SECURITY.md no longer tells reporters to avoid public issues"
    );

    // And the project must actually point people at the policy.
    let readme = std::fs::read_to_string("README.md").expect("README.md");
    assert!(
        readme.contains("SECURITY.md"),
        "README does not link SECURITY.md, so the policy is unreachable from \
         the front door"
    );
}

/// Regression guard: the Code of Conduct once shipped with the enforcement
/// contact deleted (the INSERT-CONTACT-METHOD placeholder removed rather
/// than filled), leaving no way to report an incident.
#[test]
fn code_of_conduct_has_enforcement_contact() {
    let coc = std::fs::read_to_string("CODE_OF_CONDUCT.md").expect("CODE_OF_CONDUCT.md");
    assert!(
        !coc.to_ascii_uppercase().contains("[INSERT"),
        "unfilled Contributor Covenant placeholder"
    );
    // Anchor on the exact heading — "## Enforcement Responsibilities"
    // comes first in the covenant and would otherwise win the split.
    let enforcement = coc
        .split("## Enforcement\n")
        .nth(1)
        .expect("Enforcement section present");
    assert!(
        enforcement.contains('@') && enforcement.contains("mailto:"),
        "Enforcement section must name a working contact (mailto link)"
    );
    // And the repo actually points people at it.
    let readme = std::fs::read_to_string("README.md").expect("README.md");
    assert!(
        readme.contains("CODE_OF_CONDUCT.md"),
        "README must link the Code of Conduct"
    );
}

/// The man page must track the crate: its .TH version and LICENSE section
/// once rotted to "0.4.18" / "GPL-3.0-only" while Cargo.toml said 0.5.2 /
/// "MIT OR Apache-2.0" — a licensing contradiction, not just staleness.
#[test]
fn man_page_version_and_license_match_cargo() {
    let man = include_str!("../man/sipnab.1");
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        man.contains(&format!("\"sipnab {version}\"")),
        "man/sipnab.1 .TH version must be the crate version {version}"
    );
    assert!(
        !man.contains("GPL"),
        "man/sipnab.1 license drifted: Cargo.toml says MIT OR Apache-2.0"
    );
    assert!(
        man.contains("MIT OR Apache-2.0"),
        "man/sipnab.1 must state the MIT OR Apache-2.0 license"
    );
}

/// "Current version" strings sprinkled through the install/benchmark docs
/// must equal the crate version — they sit outside the pre-commit gate that
/// keeps website/config.toml in sync, so they rot on every release without
/// this guard. Historical references (e.g. the benchmark provenance
/// "0.4.16") are deliberately NOT matched.
#[test]
fn docs_current_version_markers_match_cargo() {
    let version = env!("CARGO_PKG_VERSION");

    // Markers that tell a reader WHICH VERSION TO DOWNLOAD track the last
    // PUBLISHED release, not the crate version in the tree. They are two
    // different facts, and this list used to conflate them exactly the way
    // `/download` did before `published_version` existed: a release commit
    // bumps `Cargo.toml`, this gate then demanded the docs say the new number,
    // and for the whole commit -> CI -> tag -> release-build window the
    // documented `SIPNAB_VERSION=x.y.z` named a release that did not exist. A
    // reader copying that line got a 404 from install.sh.
    //
    // `install.sh` itself is unaffected — with `SIPNAB_VERSION` unset it asks
    // the API for the latest release — so this only ever bit the person who
    // followed the documented pinned example.
    let published = regex::Regex::new(r#"(?m)^published_version = "([^"]+)""#)
        .unwrap()
        .captures(include_str!("../website/config.toml"))
        .expect("website/config.toml has no published_version")[1]
        .to_string();
    let download_markers: &[(&str, &str, &str)] = &[
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"SIPNAB_VERSION=(\d+\.\d+\.\d+)",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"e\.g\. (\d+\.\d+\.\d+)",
        ),
        // Every rpm variant, not just the x86_64 standard one. The pattern was
        // `-1\.x86_64\.rpm`, which pinned line one of three `rpm -i` recipes
        // sitting in the same section -- the `-noaudio` and `aarch64` lines went
        // ungated and were still naming 0.5.63 while the gated line moved. Same
        // section, same copy-paste, same 404; the gate simply could not see two
        // thirds of it. The arch and variant are alternations so a new package
        // flavor is covered the day it is documented.
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"sipnab-(\d+\.\d+\.\d+)-1\.(?:x86_64|aarch64)(?:-noaudio)?\.rpm",
        ),
        // The alternation above gates the version of whatever `rpm -i` recipes
        // the page HAPPENS to carry. It says nothing about one that is missing,
        // and one was: a release publishes four rpms, while install.md
        // documented three commands -- x86_64, x86_64-noaudio, aarch64. The
        // published `sipnab-<version>-1.aarch64-noaudio.rpm` had no line naming
        // it anywhere on the page, so an arm64 headless reader had to guess the
        // filename off the packaging table. Same section and same copy-paste as
        // the drift the comment above records, one step further along: there the
        // gate could not see two thirds of the recipes, here it could not see
        // that a quarter of the packages had no recipe at all.
        //
        // Each entry below pins one exact variant, so the loop's "expected at
        // least one" assertion fires the moment a recipe disappears -- and each
        // still tracks published_version like every other download marker. Add
        // one whenever the release workflow grows a package flavor, and add the
        // `rpm -i` line it gates.
        //
        // Only docs/install.md is listed: website/content/docs/install.md is
        // generated from it, and site_pages_mirror_is_current compares the two
        // byte-for-byte, so the mirror cannot carry a different set of recipes.
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"rpm -i sipnab-(\d+\.\d+\.\d+)-1\.x86_64\.rpm",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"rpm -i sipnab-(\d+\.\d+\.\d+)-1\.x86_64-noaudio\.rpm",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"rpm -i sipnab-(\d+\.\d+\.\d+)-1\.aarch64\.rpm",
        ),
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"rpm -i sipnab-(\d+\.\d+\.\d+)-1\.aarch64-noaudio\.rpm",
        ),
        (
            "website/content/docs/install.md",
            include_str!("../website/content/docs/install.md"),
            r"e\.g\. (\d+\.\d+\.\d+)",
        ),
    ];
    for (path, text, pattern) in download_markers {
        let re = regex::Regex::new(pattern).unwrap();
        let mut matched = false;
        for cap in re.captures_iter(text) {
            matched = true;
            assert_eq!(
                &cap[1], published,
                "{path}: download marker '{pattern}' names {} but the last \
                 PUBLISHED release is {published} — a reader copying this would \
                 fetch a version that does not exist yet. Download instructions \
                 track published_version, not Cargo.toml.",
                &cap[1]
            );
        }
        assert!(
            matched,
            "{path}: expected at least one '{pattern}' marker; the doc changed \
             — update the marker list"
        );
    }

    // (path, contents, marker regex whose capture 1 must be the CRATE version)
    let sources: &[(&str, &str, &str)] = &[
        (
            "docs/install.md",
            include_str!("../docs/install.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        (
            "website/content/docs/install.md",
            include_str!("../website/content/docs/install.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        // The benchmarks pages deliberately have NO current-version marker.
        //
        // They used to. Both carried "the current release X is N later", and
        // this list required X to equal the crate version — so every release
        // mechanically advanced it, and the sentence went on looking current
        // while the measurement behind it aged twenty-nine releases. The gate
        // was not merely failing to catch the staleness; it was manufacturing
        // the appearance of freshness.
        //
        // The pages now state the release they were MEASURED on, which is a
        // historical fact and must not track Cargo.toml. It is gated instead by
        // benchmark_pages_agree_on_what_was_measured, below.
        // The `sipnab X.Y.Z (…) features:` sample output was only gated in the
        // install pages; the MCP walkthroughs print it too.
        //
        // Scope note: this pattern only matches the form with a commit hash in
        // parentheses. A bare `sipnab 0.5.20 features:` line once slipped
        // through and sat stale for 23 releases. It is gone now, and the
        // remaining version mention in those pages is a deliberately historical
        // "verified at 0.5.20" — which does not rot — so there is nothing left
        // for a no-paren pattern to guard. Do not reintroduce a bare
        // `sipnab <version> features:` sample without gating it.
        (
            "docs/mcp-deploy.md",
            include_str!("../docs/mcp-deploy.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        (
            "website/content/docs/mcp-deploy.md",
            include_str!("../website/content/docs/mcp-deploy.md"),
            r"sipnab (\d+\.\d+\.\d+) \(",
        ),
        // `website/content/docs/api.md` used to be gated here on an
        // `as of <version>` marker, and the entry is gone for the same reason
        // the benchmark pages lost theirs.
        //
        // The sentence it tracked said "as of <version> nothing in the capture
        // path records into sipnab_security_alerts_total", and this gate
        // advanced that version on every release. The recording call landed in
        // `AlertEngine::fire`, `firing_an_alert_moves_the_metric` stopped being
        // ignored, and the sentence became false — while this gate went on
        // dutifully renumbering it, which made a stale claim look freshly
        // checked. The gate was not failing to catch the rot. It was dressing
        // it up.
        //
        // The paragraph now describes what the metric does and dates the old
        // behavior as history ("up to 0.5.74"), which must NOT track
        // Cargo.toml. Nothing on that page names a current version any more, so
        // nothing there belongs in this list.
        // The `server_capabilities` sample in the diagnostic cookbook. It is
        // real captured output, so it names the build that produced it — which
        // is exactly why it needs gating rather than trusting: the recipes are
        // there to be recognized mid-incident, and a reader comparing their own
        // output against a version three releases stale has to work out whether
        // the difference matters.
        //
        // Distinct from the `sipnab X.Y.Z (` pattern above because this is a
        // JSON field rather than a `--version` line. It went in ungated and is
        // listed here rather than left to rot the way the bare
        // `sipnab 0.5.20 features:` sample did for 23 releases.
        //
        // `\s*` after the colon, and that is the third time this gate has been
        // caught by the same shape. A sample written as compact JSON --
        // `"version":"0.5.73"`, no space -- sat on THIS page, already in this
        // list, and drifted 50 releases because the pattern demanded a space
        // the line did not have. A gate that reads one spelling of the thing
        // it watches reports green on every other spelling.
        (
            "docs/mcp-deploy.md",
            include_str!("../docs/mcp-deploy.md"),
            r#""version":\s*"(\d+\.\d+\.\d+)""#,
        ),
        (
            "website/content/docs/mcp-deploy.md",
            include_str!("../website/content/docs/mcp-deploy.md"),
            r#""version":\s*"(\d+\.\d+\.\d+)""#,
        ),
        // The same server_capabilities sample appears in the MCP reference.
        // Gating only the walkthrough left this one drifting: it still named
        // 0.5.69 after the crate moved to 0.5.70, in the same release that
        // added the gate. Two copies of one sample, one of them watched.
        (
            "docs/mcp-tools.md",
            include_str!("../docs/mcp-tools.md"),
            r#""version":\s*"(\d+\.\d+\.\d+)""#,
        ),
        (
            "website/content/docs/mcp-tools.md",
            include_str!("../website/content/docs/mcp-tools.md"),
            r#""version":\s*"(\d+\.\d+\.\d+)""#,
        ),
    ];
    for (path, text, pattern) in sources {
        let re = regex::Regex::new(pattern).unwrap();
        let mut matched = false;
        for cap in re.captures_iter(text) {
            matched = true;
            assert_eq!(
                &cap[1], version,
                "{path}: current-version marker '{pattern}' names {} but the crate \
                 is {version} — update the doc (or this marker list)",
                &cap[1]
            );
        }
        assert!(
            matched,
            "{path}: expected at least one '{pattern}' marker; the doc changed — \
             update the marker list"
        );
    }
}

// ---------------------------------------------------------------------------
// The benchmarks page exists twice — docs/benchmarks.md (source of the GitHub
// Wiki) and website/content/docs/benchmarks.md (the site) — with deliberately
// different framing but the SAME measured data. A re-benchmark once landed
// only on the website (0.5.18 numbers) while the wiki kept publishing the
// 0.4.16 tables plus a perf claim the same PR had retracted. The prose may
// differ; the tables may not.
// ---------------------------------------------------------------------------

/// The markdown table rows of docs/benchmarks.md and the website benchmarks page are identical.
#[test]
fn benchmark_tables_match_between_docs_and_website() {
    /// The markdown table rows (lines starting with `|`) of a document,
    /// trailing whitespace trimmed.
    fn rows(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|l| l.starts_with('|'))
            .map(str::trim_end)
            .collect()
    }
    let docs = rows(include_str!("../docs/benchmarks.md"));
    let site = rows(include_str!("../website/content/docs/benchmarks.md"));
    assert_eq!(
        docs, site,
        "benchmark tables differ between docs/benchmarks.md (wiki source) and \
         website/content/docs/benchmarks.md — re-benchmarks must update BOTH \
         files in the same commit, or the wiki publishes stale numbers"
    );
}

/// `response_class()` agrees with the classification in the reference page.
///
/// `docs/sip-response-codes.md` groups all 75 registry codes under seven class
/// headings, and `sipnab::sip::response_codes::response_class` decides the same
/// question in code. Two statements of one fact is the bug class this repository
/// keeps finding: the dialog state machine restated it a third way, as inline
/// ranges across four handlers, and two defects lived in the gaps.
///
/// Reads the page rather than a copy of it, so adding a code to the doc without
/// teaching the classifier fails here.
#[test]
fn response_class_matches_the_documented_table() {
    use sipnab::sip::response_codes::{ResponseClass, response_class};

    let doc = include_str!("../docs/sip-response-codes.md");
    // Section heading -> class. The page titles them for a reader; map back.
    let heading_class = |h: &str| -> Option<ResponseClass> {
        match h {
            "1xx provisional" => Some(ResponseClass::Provisional),
            "2xx success" => Some(ResponseClass::Success),
            "3xx redirect" => Some(ResponseClass::Redirect),
            "Challenge" => Some(ResponseClass::Challenge),
            "Canceled" => Some(ResponseClass::Canceled),
            "Declined" => Some(ResponseClass::Declined),
            "Failure" => Some(ResponseClass::Failure),
            _ => None,
        }
    };
    let row = regex::Regex::new(r"(?m)^\| `(\d{3})` \|").unwrap();
    let head = regex::Regex::new(r"(?m)^## (.+)$").unwrap();

    let mut current: Option<ResponseClass> = None;
    let mut checked = 0usize;
    for line in doc.lines() {
        if let Some(c) = head.captures(line) {
            current = heading_class(c[1].trim());
            continue;
        }
        let Some(c) = row.captures(line) else {
            continue;
        };
        let Some(expected) = current else { continue };
        let code: u16 = c[1].parse().expect("three digits");
        assert_eq!(
            response_class(code),
            expected,
            "docs/sip-response-codes.md files {code} under {expected:?}, but \
             response_class() says {:?}",
            response_class(code)
        );
        checked += 1;
    }
    assert_eq!(
        checked, 75,
        "checked {checked} codes against the page, expected all 75 — the table \
         shape changed and this gate is reading less than it claims"
    );
}

/// Every `DialogState` value appears in the docs that enumerate them.
///
/// Three pages list the states as prose — the filter DSL's valid values, the
/// REST API's `state` query parameter, and the `sipnab_dialogs_total{state}`
/// metric — and a fourth enumeration lives in `config_wiring_test`. None of the
/// four is compiler-enforced, unlike the five `match` arms over the enum, which
/// cannot compile if a variant is missed.
///
/// That asymmetry is the whole reason this exists: adding `Redirected` broke
/// five matches loudly and would have left four lists quietly wrong. A filter
/// value nobody documents is a filter nobody uses.
#[test]
fn documented_dialog_states_cover_the_enum() {
    // The enumeration, mirrored from `DialogState`. Adding a variant without
    // adding it here passes; adding it here without documenting it fails, which
    // is the direction that matters — the docs are what a reader has.
    const STATES: [&str; 13] = [
        "Trying",
        "Ringing",
        "InCall",
        "Completed",
        "Canceled",
        "Failed",
        "Redirected",
        "Registered",
        "Expired",
        "Pending",
        "Active",
        "Terminated",
        "Transferring",
    ];
    let pages: [(&str, &str); 2] = [
        ("docs/filter-dsl.md", include_str!("../docs/filter-dsl.md")),
        ("docs/rest-api.md", include_str!("../docs/rest-api.md")),
    ];
    for (path, text) in pages {
        for state in STATES {
            assert!(
                text.contains(&format!("`{state}`")),
                "{path} never mentions the `{state}` dialog state — a reader \
                 cannot filter on a value the page does not list"
            );
        }
    }
}

/// Docs that state the fuzz-target count as current must match the tree.
///
/// `docs/fault-model.md` also names every target, so a new one added without
/// touching that list leaves the page describing a fuzz surface smaller than
/// the real one — a security-facing page understating security coverage.
/// Nothing checked either the number or the names.
#[test]
fn fuzz_target_count_and_names_match_the_tree() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut actual: Vec<String> = std::fs::read_dir(repo.join("fuzz/fuzz_targets"))
        .expect("fuzz/fuzz_targets must exist")
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.extension()? != "rs" {
                return None;
            }
            Some(p.file_stem()?.to_str()?.to_string())
        })
        .collect();
    actual.sort();

    let n = actual.len();
    for (path, text) in [
        (
            "docs/fault-model.md",
            include_str!("../docs/fault-model.md"),
        ),
        (
            "docs/architecture.md",
            include_str!("../docs/architecture.md"),
        ),
    ] {
        assert!(
            text.contains(&format!("{n} targets")) || text.contains(&format!("targets ({n})")),
            "{path} does not state the real fuzz-target count ({n}); a target was \
             added or removed without updating the docs that advertise it"
        );
    }

    // fault-model.md also enumerates them. The prose uses deliberate shorthand
    // (`sdp` for sdp_parser, `websocket` for websocket_frame), so matching
    // names one-to-one would be brittle and would rot the first time a target
    // is called something like `foo_decoder`. The durable invariant is that the
    // list is as long as the directory: that catches a target added with the
    // count bumped but the list left short, which is the realistic mistake.
    let fault = include_str!("../docs/fault-model.md");
    let listed = fault
        .split_once("targets:")
        .and_then(|(_, rest)| rest.split_once('.'))
        .map(|(list, _)| list.split(',').filter(|s| !s.trim().is_empty()).count())
        .expect("docs/fault-model.md no longer enumerates the fuzz targets after 'targets:'");
    assert_eq!(
        listed, n,
        "docs/fault-model.md names {listed} fuzz targets but {n} exist in \
         fuzz/fuzz_targets/ — the security-facing page is describing a smaller \
         fuzz surface than the tree actually has"
    );
}

/// The ROOT `Cargo.lock` pins sipnab's own version and must match the crate.
///
/// The sibling gate below has covered `fuzz/Cargo.lock` since 0.5.48. This one
/// did not exist, and the asymmetry had exactly the effect you would predict:
/// the fuzz lockfile was caught at every release and the root lockfile was
/// caught by nobody. 0.5.120 shipped a tag naming 0.5.119 here, and 0.5.121
/// shipped a tag naming 0.5.120 — the second one AFTER the first was noticed,
/// because the only thing standing between it and the tag was somebody
/// remembering to look.
///
/// The artefacts are unaffected: cargo rewrites the lockfile during the build,
/// so the published binaries carry the right version. What ships wrong is the
/// tagged SOURCE — a tree whose `Cargo.toml` and `Cargo.lock` disagree about
/// what release it is, which is a thing anyone reproducing a build has to
/// explain to themselves.
///
/// It is the same failure mode the fuzz gate was written for, and the fix is
/// the same: `cargo update -p sipnab` (or any cargo command) and commit the
/// result with the bump.
#[test]
fn root_lockfile_pins_the_current_crate_version() {
    let manifest = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml");
    let crate_version = manifest
        .lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .and_then(|v| v.split('"').next())
        .expect("Cargo.toml carries a version");

    // Read what GIT holds, never the working tree.
    //
    // Any cargo command rewrites Cargo.lock to match Cargo.toml, and a test
    // runs under cargo -- so by the time this line executes, the file on disk
    // has already been repaired and agrees with the manifest no matter what
    // was committed. A first version of this gate read the file and could not
    // fail: mutating the lockfile to the previous version left the test green,
    // because cargo had fixed it before the assertion ran.
    //
    // That self-healing is also WHY the defect ships. Locally everything looks
    // right; the staleness exists only in the committed bytes. So the index is
    // what gets checked, which is the content about to become a commit.
    //
    // The sibling fuzz gate below reads its file directly and is sound doing
    // so, for a reason worth stating: `cargo test` at the repository root
    // never touches `fuzz/Cargo.lock`, so nothing repairs it underfoot.
    let staged = std::process::Command::new("git")
        .args(["show", ":Cargo.lock"])
        .output()
        .expect("git show :Cargo.lock");
    assert!(
        staged.status.success(),
        "could not read Cargo.lock from the git index: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    let lock = String::from_utf8(staged.stdout).expect("Cargo.lock is utf8");
    let locked = lock
        .split("\n[[package]]\n")
        .find(|block| block.starts_with("name = \"sipnab\"\n"))
        .and_then(|block| block.lines().find_map(|l| l.strip_prefix("version = \"")))
        .and_then(|v| v.split('"').next())
        .expect("Cargo.lock carries a [[package]] entry for sipnab");

    assert_eq!(
        locked, crate_version,
        "the COMMITTED Cargo.lock pins sipnab {locked} but the crate is \
         {crate_version}. The file on disk is already correct -- cargo repairs \
         it -- so this is only ever fixed by STAGING it: `cargo update -p \
         sipnab && git add Cargo.lock`, with the version bump. Left behind, \
         the tag carries a tree whose manifest and lockfile disagree about \
         which release it is, which is what 0.5.120 and 0.5.121 both shipped."
    );
}

/// `fuzz/Cargo.lock` pins sipnab's own version and must match the crate.
///
/// The fuzz workspace is separate, so a hand-edited version bump updates
/// `Cargo.toml`, `website/config.toml` and the man page — all of which are
/// gated — and silently leaves this one behind. It happened at 0.5.48, which
/// shipped with the lockfile still naming 0.5.47, and nothing anywhere noticed:
/// no hook, no workflow, no test looked at this file.
#[test]
fn fuzz_lockfile_pins_the_current_crate_version() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock = std::fs::read_to_string(repo.join("fuzz/Cargo.lock"))
        .expect("fuzz/Cargo.lock must exist — the fuzz workspace is committed");

    // The [[package]] block whose name is sipnab; its `version` is the pin.
    let pinned = lock
        .split("[[package]]")
        .find(|block| block.contains("name = \"sipnab\""))
        .and_then(|block| {
            block
                .lines()
                .find_map(|l| l.trim().strip_prefix("version = "))
                .map(|v| v.trim().trim_matches('"').to_string())
        })
        .expect("no sipnab [[package]] entry in fuzz/Cargo.lock");

    assert_eq!(
        pinned,
        env!("CARGO_PKG_VERSION"),
        "fuzz/Cargo.lock pins sipnab {pinned} but the crate is {} — run \
         `cargo update -p sipnab --manifest-path fuzz/Cargo.toml` (or any cargo \
         command in fuzz/) and commit the result with the version bump",
        env!("CARGO_PKG_VERSION")
    );
}

/// Both benchmark pages must name the same measured release and date, and that
/// release must actually exist.
///
/// This replaces the old `current release X.Y.Z` marker, which required the
/// pages to name the crate version and so re-stamped them as current at every
/// release without anything being re-measured. What matters is not that the
/// page names today's version — it is that both trees agree on which artifact
/// produced the numbers, and that it is a real published one.
#[test]
fn benchmark_pages_agree_on_what_was_measured() {
    let re = regex::Regex::new(
        r"released (\d+\.\d+\.\d+) artifact, checksum-verified, (\d{4}-\d{2}-\d{2})",
    )
    .unwrap();

    let mut seen: Option<(String, String)> = None;
    for (path, text) in [
        ("docs/benchmarks.md", include_str!("../docs/benchmarks.md")),
        (
            "website/content/docs/benchmarks.md",
            include_str!("../website/content/docs/benchmarks.md"),
        ),
    ] {
        let cap = re.captures(text).unwrap_or_else(|| {
            panic!(
                "{path}: no 'released X.Y.Z artifact, checksum-verified, YYYY-MM-DD' \
                 statement. Every number on this page comes from one artifact on one \
                 day; if the page will not say which, the numbers are unattributable."
            )
        });
        let found = (cap[1].to_string(), cap[2].to_string());
        match &seen {
            None => seen = Some(found),
            Some(first) => assert_eq!(
                first, &found,
                "the two benchmark pages disagree about what was measured \
                 ({first:?} vs {found:?}) — a re-benchmark must update both trees"
            ),
        }
    }

    // You cannot have measured a release that does not exist yet.
    let (measured, _) = seen.expect("at least one benchmarks page");
    let crate_version = env!("CARGO_PKG_VERSION");
    let parse = |v: &str| -> Vec<u32> { v.split('.').map(|p| p.parse().unwrap()).collect() };
    assert!(
        parse(&measured) <= parse(crate_version),
        "benchmarks claim to be measured on {measured}, which is newer than the \
         crate version {crate_version}"
    );
}

/// The benchmark harness the benchmarks page cites must exist in the repo.
///
/// From 0.5.18 to 0.5.46 the page claimed "every number here is reproducible"
/// and called the listed commands "the full recipe", while the corpus generator
/// sat in an unpublished repository. Nobody could re-run a single number,
/// including on the reference host the methodology names. Nothing detected it
/// because nothing looked.
#[test]
fn benchmark_harness_is_published() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for f in [
        "bench/carrier.py",
        "bench/scaling.sh",
        "bench/compare.sh",
        "bench/README.md",
    ] {
        assert!(
            repo.join(f).is_file(),
            "{f} is missing, but docs/benchmarks.md tells readers to run it. \
             A reproducibility claim whose harness is absent is not a claim."
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["bench/scaling.sh", "bench/compare.sh"] {
            let mode = std::fs::metadata(repo.join(f))
                .expect("harness script metadata")
                .permissions()
                .mode();
            assert!(
                mode & 0o111 != 0,
                "{f} is not executable, so the documented `bench/…` invocation fails"
            );
        }
    }
}

/// The corpus figures quoted on the benchmarks page must be what the generator
/// actually produces.
///
/// The page names an exact composition — 535,000 packets, 35,000 SIP, 500,000
/// RTP, 93.5% — and readers use those to confirm they rebuilt the right corpus.
/// Generating the full 128 MB in a unit test would be wasteful, so this runs a
/// 1/100-scale corpus and requires it to scale exactly. Change the packet mix
/// and this fails rather than letting the page describe a corpus that no longer
/// exists.
#[test]
fn carrier_generator_produces_the_documented_corpus() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let tmp = std::env::temp_dir().join(format!("sipnab-carrier-{}.pcap", std::process::id()));

    let out = std::process::Command::new("python3")
        .arg(repo.join("bench/carrier.py"))
        .args(["--calls", "50", "--quiet", "--out"])
        .arg(&tmp)
        .current_dir(repo)
        .output()
        .expect("run bench/carrier.py — python3 must be on PATH");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        out.status.success(),
        "bench/carrier.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 50 calls is exactly 1/100 of the documented corpus, so the sample's
    // composition must be the published one divided by 100.
    let summary = String::from_utf8_lossy(&out.stdout);
    let expected = "5350 packets (350 SIP, 5000 RTP = 93.5%), 50 calls";
    assert!(
        summary.contains(expected),
        "bench/carrier.py no longer produces the documented packet mix.\n  \
         expected to contain: {expected}\n  got: {}",
        summary.trim()
    );

    // …and the page must still quote the 100x figures that sample implies.
    for doc in [
        include_str!("../docs/benchmarks.md"),
        include_str!("../website/content/docs/benchmarks.md"),
    ] {
        for claim in ["535,000 packets", "35,000 SIP", "500,000 RTP", "93.5%"] {
            assert!(
                doc.contains(claim),
                "benchmarks page no longer states {claim:?}, but bench/carrier.py \
                 still produces it at --calls 5000 (100x the generated sample)"
            );
        }
    }
}

/// Every capability an operator can choose must be findable on the HOMEPAGE.
///
/// The README table (below) proves a feature is *documented*. This proves it is
/// *discoverable*, which is a different thing and the one that failed: the eBPF
/// TLS capture shipped in 0.5.102 fully documented -- a developer page, two
/// cookbook recipes, six flags with runnable examples -- and the word "eBPF"
/// appeared ZERO times on the homepage and zero times on the internals index.
/// It was written up throughout as "uprobe" and "BPF", which is accurate and is
/// not the word anyone searches for. The owner could not find his own feature.
///
/// So each non-default, user-facing feature names the phrase a reader would
/// actually look for. The map is explicit rather than derived, because
/// `bpf` -> "eBPF" is a judgement about vocabulary that no rule can infer --
/// and adding a feature without deciding how a reader finds it fails here.
#[test]
fn the_homepage_names_every_capability_a_reader_would_search_for() {
    let home = include_str!("../website/templates/index.html");
    // (cargo feature, the phrase a reader searches for)
    let must_appear: &[(&str, &str)] = &[
        ("tls", "TLS"),
        ("hep", "HEP"),
        ("mcp", "MCP"),
        ("metrics", "Prometheus"),
        ("plugins", "plugin"),
        ("wasm", "browser"),
        // The one this test exists for.
        ("bpf", "eBPF"),
    ];
    let manifest = include_str!("../Cargo.toml");
    let features_block = manifest
        .split("[features]")
        .nth(1)
        .expect("Cargo.toml has a [features] table")
        .split("\n[")
        .next()
        .expect("features table terminates");

    let mut missing = Vec::new();
    for (feature, phrase) in must_appear {
        assert!(
            features_block.contains(&format!("{feature} = [")),
            "the map names a `{feature}` feature that Cargo.toml does not define"
        );
        if !home.contains(phrase) {
            missing.push(format!("`{feature}` -> no \"{phrase}\" on the homepage"));
        }
    }
    assert!(
        missing.is_empty(),
        "a capability a reader cannot find is not documented, however well it is \
         written up elsewhere:\n  {}",
        missing.join("\n  ")
    );
}

/// Whether a markdown feature table has a ROW whose first cell is `name`.
///
/// Both tables spell the first cell the same way — a pipe, optional spaces, the
/// name in backticks — so one reader serves both.
fn has_feature_row(page: &str, name: &str) -> bool {
    let cell = format!("`{name}`");
    page.lines().any(|line| {
        line.trim_start()
            .strip_prefix('|')
            .is_some_and(|rest| rest.trim_start().starts_with(&cell))
    })
}

/// Every `[features]` key in Cargo.toml must appear in BOTH feature tables —
/// the README's and the install page's.
///
/// `metrics` is a DEFAULT feature that was absent from the README for several
/// releases, so a reader could not discover it existed. The install page then
/// repeated the failure with `vcon`: the gate covered README.md alone, so the
/// page a reader is SENT to for feature questions — `docs/library.md` answers
/// every one of them by pointing at `install.md#feature-flags` — was the one
/// place that denied the feature existed. A table a reader is routed to has to
/// be under the same gate as the one they might stumble on.
#[test]
fn feature_tables_cover_every_cargo_feature() {
    let manifest = include_str!("../Cargo.toml");
    let readme = include_str!("../README.md");
    let install = include_str!("../docs/install.md");

    let features_block = manifest
        .split("[features]")
        .nth(1)
        .expect("Cargo.toml has a [features] section")
        .split("\n[")
        .next()
        .expect("features section terminates");

    let mut missing = Vec::new();
    let mut seen = 0;
    for line in features_block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, _)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name == "default" {
            continue;
        }
        seen += 1;
        // A ROW, not a mention. `contains("`vcon`")` passes on the `full`
        // row's "+ `vcon`" alone, so deleting the feature's own row leaves the
        // gate green while the reader loses the entry describing it. Verified
        // by mutation: the substring form survived that deletion.
        if !has_feature_row(readme, name) {
            missing.push(format!("README.md: {name}"));
        }
        if !has_feature_row(install, name) {
            missing.push(format!("docs/install.md: {name}"));
        }
    }

    assert_eq!(
        seen, 14,
        "feature extraction found {seen} features, expected 14. Bump when a \
         feature is added; a drop means the parser stopped reading Cargo.toml's \
         table and the comparison below narrowed."
    );
    assert!(
        missing.is_empty(),
        "a feature table is missing an entry: {}",
        missing.join(", ")
    );
}

/// Every `[theme]` color slot must be documented in both theme guides, and the
/// slot count quoted in both config references must match `ThemeConfig`.
///
/// This closes a drift that shipped: `status_bg` is applied by
/// `tui::theme::apply_color` and has a dedicated round-trip test, yet both
/// theme guides told readers it was "not configurable", and the two config
/// references disagreed on the slot count (11 vs 10).
#[test]
fn theme_slots_are_documented_and_counted_correctly() {
    let config_rs = include_str!("../src/config.rs");

    // Fields of `pub struct ThemeConfig` — the authoritative slot list.
    let block = config_rs
        .split("pub struct ThemeConfig {")
        .nth(1)
        .expect("ThemeConfig struct not found")
        .split("\n}")
        .next()
        .expect("unterminated ThemeConfig struct");
    let slots: Vec<&str> = block
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| l.split(':').next())
        .collect();

    assert_eq!(
        slots.len(),
        12,
        "ThemeConfig field extraction found {} slots, expected 12. Bump when a \
         slot is added; a drop means the parser stopped reading the struct and \
         the documentation comparison below narrowed with it.",
        slots.len()
    );

    // `highlight` is a legacy alias for `selected`, counted separately in prose.
    let semantic = slots.len() - 1;

    let guides: &[(&str, &str)] = &[
        (
            "docs/theme-guide.md",
            include_str!("../docs/theme-guide.md"),
        ),
        (
            "website/content/docs/theme.md",
            include_str!("../website/content/docs/theme.md"),
        ),
    ];
    let mut missing = Vec::new();
    for (name, text) in guides {
        for slot in &slots {
            if !text.contains(&format!("`{slot}`")) {
                missing.push(format!("{name}: `{slot}`"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "theme guides do not document every [theme] slot:\n  {}",
        missing.join("\n  ")
    );

    let refs: &[(&str, &str)] = &[
        (
            "docs/config-reference.md",
            include_str!("../docs/config-reference.md"),
        ),
        (
            "website/content/docs/config.md",
            include_str!("../website/content/docs/config.md"),
        ),
    ];
    let expected = format!("{semantic} semantic color slots");
    let mut wrong = Vec::new();
    for (name, text) in refs {
        if !text.contains(&expected) {
            wrong.push(name.to_string());
        }
    }
    assert!(
        wrong.is_empty(),
        "these config references do not say \"{expected}\" (ThemeConfig has \
         {} fields, one of which is the `highlight` alias): {}",
        slots.len(),
        wrong.join(", ")
    );
}

// ---------------------------------------------------------------------------
// Third-party notices: attribution is an obligation, and a stale file is a
// broken one.
// ---------------------------------------------------------------------------

/// `THIRD-PARTY-NOTICES.md` equals what the generator produces from the real
/// dependency graph today.
///
/// MIT and Apache-2.0 both require the notice to travel with the binary, and
/// libasound is LGPL-2.1-or-later, so this file is a license obligation rather
/// than a courtesy. Hand-maintained it would go stale on the first
/// `cargo update` with nothing to notice — the same shape as every other gap
/// this suite exists for, except the consequence is legal rather than cosmetic.
#[test]
fn third_party_notices_are_current() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let tmp = std::env::temp_dir().join(format!("sipnab-notices-{}.md", std::process::id()));

    let out = std::process::Command::new("python3")
        .arg(repo.join("scripts/build-third-party-notices.py"))
        .arg(&tmp)
        .current_dir(repo)
        .output()
        .expect("run scripts/build-third-party-notices.py — python3 and cargo must be on PATH");
    assert!(
        out.status.success(),
        "build-third-party-notices.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let fresh = std::fs::read_to_string(&tmp).expect("generated notices");
    let committed =
        std::fs::read_to_string(repo.join("THIRD-PARTY-NOTICES.md")).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);

    assert_eq!(
        fresh.trim_end(),
        committed.trim_end(),
        "THIRD-PARTY-NOTICES.md is stale — the dependency graph changed. \
         Regenerate with `python3 scripts/build-third-party-notices.py` and commit."
    );
}

/// The notices name every system library the released binaries link, with the
/// license that actually applies.
///
/// These are resolved by the host's package manager, never by cargo, so they
/// cannot be derived from the lockfile and cannot be caught by the currency
/// check above. libasound is the only copyleft component sipnab touches; if its
/// entry ever disappears, the notice obligation is silently unmet.
#[test]
fn third_party_notices_cover_system_libraries() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let notices = std::fs::read_to_string(repo.join("THIRD-PARTY-NOTICES.md"))
        .expect("THIRD-PARTY-NOTICES.md must exist — it ships in every release artifact");

    for (lib, license) in [
        ("libpcap", "BSD-3-Clause"),
        ("libasound", "LGPL-2.1-or-later"),
    ] {
        assert!(
            notices.contains(lib),
            "THIRD-PARTY-NOTICES.md does not mention {lib}, which the released \
             binaries link at runtime"
        );
        assert!(
            notices.contains(license),
            "THIRD-PARTY-NOTICES.md does not state {license} (for {lib})"
        );
    }

    // The notices are worthless if they do not ship. Every release artifact
    // that carries LICENSE-MIT must carry these too.
    let release = std::fs::read_to_string(repo.join(".github/workflows/release.yml"))
        .expect("read release.yml");
    assert!(
        release.contains("THIRD-PARTY-NOTICES.md"),
        "release.yml does not package THIRD-PARTY-NOTICES.md — the notices would \
         exist in the repository and reach nobody who downloads a binary"
    );
}

/// The MCP tool table must list every tool the server registers.
///
/// `docs/mcp.md`'s table listed seven; the server registers eleven. The three
/// missing ones — `search_messages`, `tail_dialogs`, `security_findings` —
/// were documented in the prose below it, so nothing was factually wrong and
/// no link was dead. A reader scanning the table for what MCP can do simply
/// would not have learned they exist. (`stats` was missing from both copies of
/// the page until the merge.)
///
/// Ground truth is the `#[tool(name = "…")]` attributes, not a second list.
#[test]
fn mcp_tool_table_lists_every_registered_tool() {
    let server = std::fs::read_to_string("src/mcp/server.rs").expect("src/mcp/server.rs");
    let registered: BTreeSet<String> = regex::Regex::new(r#"name = "([a-z_]+)""#)
        .expect("regex")
        .captures_iter(&server)
        .map(|c| c[1].to_string())
        .collect();
    // Raised 29 -> 30 by `save_findings`, the first write verb on this surface.
    // Raised 31 -> 32 by `show_evidence`, which follows a frame pointer back
    // to the bytes it names — the half of #128 that makes a `frame_ref` on a
    // fact something a caller can actually check.
    // Raised 30 -> 31 by `find_correlated`, which exposes the multi-leg
    // correlation engine that had existed in DialogStore with no way to reach it.
    // LOWERED 32 -> 31 by folding `stats` into `capture_status`: the two shared
    // six identical fields, so orienting cost two calls for the same numbers.
    // A DECREASE here is normally suspicious; this one is a deliberate merge.
    // Raised 31 -> 32 by `media_diagnostics`, which reaches the media facts
    // sipnab already computed and no MCP caller could read: the QoS marking,
    // the grounding of the clock rate the jitter was derived from, the
    // provenance of the delay term behind the published MOS, silence and
    // comfort noise, and the RTCP a remote endpoint asserted.
    // Raised 32 -> 33 by `list_tls_libraries`, which answers whether SIP over
    // TLS on this host can be read at all without keys -- and, when it cannot,
    // whether that is a fact about the host or about this server's privilege.
    // Raised 33 -> 35 by `start_tls_capture` and `stop_tls_capture`: the first
    // tools on this surface that create KERNEL state, behind their own opt-in.
    // Raised 35 -> 36 by `get_capture_report` (MCPX5). `get_dialog_report` and
    // `render_ladder` both answer for one Call-ID, so everything `--report`
    // says about the capture as a whole -- orphaned media, STUN, ICMP evidence,
    // what the caps shed -- was reachable from the CLI and the REST API and
    // from no MCP tool. An agent could be handed a count it could not expand.
    // Raised 36 -> 37 by `capture_health`, the capture-path counters read twice.
    // Raised 37 -> 38 by `export_vcon` (VCON3), which hands one observed dialog
    // to a conversation-data pipeline in the interchange format that pipeline
    // already reads, rather than in a sipnab-shaped JSON nobody else parses.
    assert_eq!(
        registered.len(),
        38,
        "found only {} #[tool(name = ...)] entries in src/mcp/server.rs — the \
         attribute shape changed and this test is no longer reading the \
         registry: {registered:?}",
        registered.len()
    );

    let doc = std::fs::read_to_string("docs/mcp-tools.md").expect("docs/mcp-tools.md");
    let table = doc
        .split_once("| Tool | Parameters | Returns |")
        .expect("docs/mcp-tools.md has no tool table")
        .1;
    let table = &table[..table.find("\n\n").unwrap_or(table.len())];
    // The name may be plain (`get_message`) or a link into its own section
    // ([`get_message`](#get_message)) — the table became a real index on
    // 2026-08-10, when every row gained a link to the tool's documentation
    // further down. Matching only the plain form made this gate report ALL 32
    // tools missing, which is a formatting change reading as a catastrophe:
    // the extraction was coupled to markup that has nothing to do with what
    // the gate is checking.
    let documented: BTreeSet<String> = regex::RegexBuilder::new(r"^\| \[?`([a-z_]+)`")
        .multi_line(true)
        .build()
        .expect("regex")
        .captures_iter(table)
        .map(|c| c[1].to_string())
        .collect();

    // An extractor that matched nothing would report every tool missing and
    // an extractor that matched everything would report none — assert it saw
    // a plausible number of rows before trusting the comparison below.
    assert!(
        documented.len() >= 32,
        "the tool-table extractor found only {} rows — its pattern no longer \
         matches the table's markup, so the comparison below is meaningless: \
         {documented:?}",
        documented.len()
    );

    let missing: Vec<_> = registered.difference(&documented).collect();
    assert!(
        missing.is_empty(),
        "these MCP tools are registered but absent from the table in \
         docs/mcp-tools.md: {missing:?}"
    );
    let phantom: Vec<_> = documented.difference(&registered).collect();
    assert!(
        phantom.is_empty(),
        "docs/mcp-tools.md documents MCP tools the server does not register: \
         {phantom:?}"
    );
}

// ---------------------------------------------------------------------------
// One fenced shell block is one clipboard payload.
//
// Every surface that publishes these files puts a single copy button on a
// fence and hands over the whole body: the site does it in
// website/templates/page.html:98 (`code.innerText`), and GitHub does it for
// docs/**, README.md and the wiki with its own button. A repository cannot
// influence GitHub's — class, data-*, <button> and <script> are all stripped
// from rendered markdown — so the only lever with three-of-three reach is the
// bytes inside the fence.
//
// A block holding two independent recipes therefore hands the reader both.
// They asked for one, they get two, and they believe they ran one. That is
// merely untidy for a `sipnab --json | jq` pair; it is an incident when the
// extra command writes: `openssl rand -hex 32 > /etc/sipnab/mcp-token`
// destroys a live MCP bearer token, after which the server serves a secret no
// configured agent has.
// ---------------------------------------------------------------------------

const SHELL_LANGS: &[&str] = &["bash", "sh", "shell", "console", "zsh"];

// SCOPE, stated because the gap is real and a reader should not assume
// otherwise: this gate reads fences whose info string names a shell. The site
// attaches its copy button to every `pre` (website/templates/page.html:90), so
// an UNLABELED fence gets a button too, and 230 of those exist in the scanned
// corpus — 132 of them command-looking. They are not checked.
//
// Scanning them by heuristic was rejected: "starts with a command-looking
// word" also matches terminal transcripts and output samples, and a gate that
// cries wolf gets muted, which is worse than one with a stated limit. Closing
// this properly means labeling those fences, which is a remediation of its
// own, not a condition of this gate.

/// First line of a block that declares itself one ordered procedure.
const SEQUENCE_MARKER: &str = "# Run all of these, in order.";

/// `(1-based line of the opening fence, info word, body)` for every fenced
/// block, tracking fence character and length so a nested ```` ```markdown ````
/// sample does not corrupt the walk.
fn fenced_with_info(text: &str) -> Vec<(usize, String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        let ch = if t.starts_with("```") {
            '`'
        } else if t.starts_with("~~~") {
            '~'
        } else {
            i += 1;
            continue;
        };
        let n = t.chars().take_while(|c| *c == ch).count();
        let info = t[n..].trim().to_string();
        // A closing fence carries no info string; an info string means opening.
        let start = i;
        let mut body = String::new();
        i += 1;
        while i < lines.len() {
            let c = lines[i].trim_start();
            if c.starts_with(&ch.to_string().repeat(n)) && c[n..].trim().is_empty() {
                break;
            }
            body.push_str(lines[i]);
            body.push('\n');
            i += 1;
        }
        i += 1;
        let word = info.split_whitespace().next().unwrap_or("").to_lowercase();
        out.push((start + 1, word, body));
    }
    out
}

/// The top-level command units in a shell fence body.
///
/// A line does not start a new unit when the previous one continues into it:
/// a trailing `\`, a quote left open across the newline, an open heredoc, or a
/// trailing `|`, `&&`, `||` or `&`. Blank and `#`-comment lines are not units.
///
/// Quote state is carried ACROSS physical lines, deliberately. Resetting it
/// per line reads the prose inside `git commit -m "…"` as separate commands,
/// which is the same mistake a blank-line heuristic makes — and a gate that
/// cries wolf gets muted, which is worse than no gate.
///
/// Heredocs are handled as prevention rather than a fix: the scanned corpus
/// contains none today, and they are the one construct that would otherwise
/// make this gate report a multi-line document body as many commands.
fn command_units(body: &str) -> Vec<String> {
    let mut starts = Vec::new();
    let mut pending = false;
    let mut here: Option<String> = None;
    let mut quote: Option<char> = None;

    for raw in body.lines() {
        if let Some(tag) = &here {
            if raw.trim() == tag.trim() {
                here = None;
            }
            continue;
        }
        let stripped = raw.trim();
        if quote.is_none() && !pending && (stripped.is_empty() || stripped.starts_with('#')) {
            continue;
        }
        if quote.is_none() && !pending {
            starts.push(raw.to_string());
        }

        // Rescan the line to carry quote state forward.
        let mut q = quote;
        let mut esc = false;
        let chars: Vec<char> = raw.chars().collect();
        for (idx, c) in chars.iter().enumerate() {
            if esc {
                esc = false;
                continue;
            }
            match q {
                None => {
                    if *c == '\\' {
                        esc = true;
                    } else if *c == '\'' || *c == '"' {
                        q = Some(*c);
                    } else if *c == '#' && (idx == 0 || chars[idx - 1].is_whitespace()) {
                        break;
                    }
                }
                Some('\'') => {
                    if *c == '\'' {
                        q = None;
                    }
                }
                Some(_) => {
                    if *c == '\\' {
                        esc = true;
                    } else if *c == '"' {
                        q = None;
                    }
                }
            }
        }
        quote = q;

        if quote.is_none() {
            let rt = raw.trim_end();
            // `<<<` is a herestring, not a heredoc: it takes no terminator, so
            // treating it as one would swallow the rest of the block.
            if !rt.contains("<<<")
                && let Some(caps) = heredoc_re().captures(rt)
            {
                here = Some(caps[1].to_string());
            }
            pending = rt.ends_with('\\')
                || rt.ends_with('|')
                || rt.ends_with("&&")
                || rt.ends_with("||")
                || rt.ends_with('&');
        } else {
            pending = false;
        }
    }
    starts
}

fn heredoc_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)"#).unwrap())
}

/// Markdown the gate scans: every **tracked** `*.md`, minus planning trees
/// and minus generated mirrors.
///
/// The file list comes from `git ls-files` rather than a directory walk, so
/// build output and scratch are excluded by definition instead of by a
/// hand-kept skip list. A walk initially reported 205 offenders against
/// `git`'s 135, the difference being `build/wiki/` — `scripts/build-wiki.py`'s
/// gitignored output — and later `.superpowers/`. Each would have been a new
/// entry in a list that only grows, and each double-reports a defect whose
/// only real fix is in `docs/`.
///
/// Mirrors are excluded rather than forgiven. Both site generators' `render()`
/// rewrites links and prepends front matter; fence bodies pass through
/// byte-identically, and that identity is gated by
/// `site_pages_mirror_is_current`. So fixing `docs/examples.md` and
/// regenerating is the only way the mirror can be green — coverage is
/// transitive and stricter than scanning it directly. Reporting the mirror
/// would point the author at a file whose own header says "do not edit".
fn scanned_markdown() -> Vec<std::path::PathBuf> {
    // Planning material, never published. Retro-editing a historical record to
    // satisfy a rendering gate would corrupt it. Same exclusion and reason as
    // link_integrity_test's docs-tree scan.
    const SKIP_DIRS: &[&str] = &["docs/superpowers/", "docs/design/", "docs/research/"];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .args(["ls-files", "*.md"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|rel| !SKIP_DIRS.iter().any(|d| rel.starts_with(d)))
        .map(|rel| root.join(rel))
        .collect()
}

/// A fenced shell block must hand the reader exactly one command, unless it
/// declares itself an ordered procedure.
#[test]
fn shell_fence_is_one_clipboard_payload() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    let mut offenders = Vec::new();
    let mut scanned = 0;

    for path in scanned_markdown() {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        if text.contains("Generated by scripts/build-site") {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        for (line, info, body) in fenced_with_info(&text) {
            if !SHELL_LANGS.contains(&info.as_str()) {
                continue;
            }
            scanned += 1;
            let first = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            if first.trim() == SEQUENCE_MARKER {
                continue;
            }
            let units = command_units(&body);
            if units.len() > 1 {
                offenders.push(format!(
                    "{rel}:{line}: one copy button hands the reader {} commands:\n      {}",
                    units.len(),
                    units
                        .iter()
                        .map(|u| u.trim().to_string())
                        .collect::<Vec<_>>()
                        .join("\n      ")
                ));
            }
        }
    }

    assert!(
        scanned >= 300,
        "only {scanned} shell fences scanned (346 at the time of writing) — the \
         walk or the fence parser stopped matching, and this gate is reporting a \
         safety it is not providing"
    );
    assert!(
        offenders.is_empty(),
        "shell fences whose single copy button hands the reader more than one \
         command — the reader believes they ran one:\n  {}\n\n\
         Fix at the source:\n  \
         - alternatives  -> one fenced block each, so each gets its own copy button\n  \
         - one procedure -> add `{SEQUENCE_MARKER}` as the first line\n  \
         - dense catalog -> drop the fence; a markdown list with inline `code` \
         has no copy button on any surface\n  \
         (Never edit a website/content/docs page carrying the generator banner \
         — fix docs/ and re-run scripts/build-site-pages.py.)\n\n\
         Scope: this asserts the button hands over exactly ONE command. It does \
         NOT assert that command is correct or safe.",
        offenders.join("\n  ")
    );
}

/// The corpus scan goes green the moment the docs are fixed, so these pin the
/// lexer itself against the defect that motivated it. Without them,
/// `command_units` could be softened to always return one unit and every gate
/// above would still pass.
#[test]
fn command_units_splits_the_shipped_two_command_block() {
    // docs/troubleshooting.md:9 as published in v0.5.55 — the block whose
    // copy button handed the reader a --call-report that wrote report.md they
    // never asked for.
    let body = "\
# All failed calls: Call-ID + response code + reason per response message
sipnab -N -I capture.pcap --filter \"state == 'Failed'\" --json \\
  | jq -c 'select(.is_request == false) | {call_id, status_code, reason}'

# Detailed report for one call (Markdown, ready for a ticket)
sipnab -I capture.pcap --call-report \"abc123@host\" --markdown > report.md
";
    let units = command_units(body);
    assert_eq!(
        units.len(),
        2,
        "the shipped two-command block must read as 2 units, got {}: {units:#?}",
        units.len()
    );
}

#[test]
fn command_units_joins_continuations_quotes_and_heredocs() {
    // Trailing backslash.
    assert_eq!(
        command_units("sipnab -N \\\n  --json \\\n  -I x.pcap\n").len(),
        1
    );
    // Pipe into a continued expression.
    assert_eq!(
        command_units("sipnab -N --json |\n  jq .call_id\n").len(),
        1
    );
    // && chain.
    assert_eq!(command_units("cd /tmp &&\n  ls\n").len(), 1);
    // A quote left open across lines: the prose inside is NOT a command. This
    // is the case a blank-line heuristic gets wrong.
    assert_eq!(
        command_units("git commit -m \"line one\n\nline two\n\nline three\"\n").len(),
        1,
        "quote state must carry across newlines"
    );
    // Heredoc body is not a series of commands.
    assert_eq!(
        command_units("cat <<'EOF' > /tmp/f\nalpha\nbeta\nEOF\n").len(),
        1
    );
    // A herestring is not a heredoc.
    assert_eq!(command_units("jq . <<< \"$x\"\necho done\n").len(), 2);
    // Comments and blanks are not units.
    assert_eq!(command_units("# just a note\n\n# another\n").len(), 0);
}

#[test]
fn sequence_marker_admits_a_declared_procedure() {
    let body = format!(
        "{SEQUENCE_MARKER}\nmkdir -p /etc/sipnab\nopenssl rand -hex 32 > /etc/sipnab/mcp-token\nchmod 0600 /etc/sipnab/mcp-token\n"
    );
    assert!(
        command_units(&body).len() > 1,
        "the procedure genuinely holds several commands"
    );
    let first = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    assert_eq!(
        first.trim(),
        SEQUENCE_MARKER,
        "and the gate admits it on the strength of the declaration alone"
    );
}

/// No documentation table repeats a row.
///
/// `THIRD-PARTY-NOTICES.md` listed `r-efi` twice under "Multi-licensed crates
/// and the license elected". The generator deduplicated with
/// `set((name, version, license))` and then emitted a row *without* the
/// version, so a crate vendored at two versions — r-efi at 5.3.0 and 6.0.0 —
/// passed the set as two distinct tuples and printed one identical row twice.
///
/// The shape generalises past that one file: a table row is a claim, and the
/// same claim made twice is either a copy-paste artifact or a key that dropped
/// the column distinguishing it. Neither is something a reader should have to
/// resolve, so this sweeps every tracked markdown file rather than the one
/// that happened to break.
///
/// Rows inside code fences are excluded — a fenced example may legitimately
/// show a repeated line.
#[test]
fn no_documentation_table_repeats_a_row() {
    /// Tracked markdown files this walk expects to see.
    // 163 -> 164: `docs/design/testing-matrix.md`, the generated surface
    // coverage matrix. One file, and the only one this change adds --
    // `docs/design/` is repo-only, so it adds nothing to the website or to
    // llms-full.txt, which a 274-row table would otherwise bloat.
    // 164 -> 165: `docs/design/vcon.md`, the Phase 0 decision on emitting
    // vCon containers. One file. A design doc has no website mirror, so it
    // costs this counter one and not two, and the pointer it gained in
    // `docs/design/backlog.md` is a row in a table that already existed.
    // 165 -> 169: the vCon pages. Attributed by measurement against `main`,
    // which carries 164: this branch adds `docs/vcon.md`,
    // `docs/internals/vcon.md`, `docs/design/vcon.md` and the two generated
    // site mirrors of the first two. 164 + 5 = 169, and the 165 this replaces
    // had accounted for one of them.
    // 169 -> 170: the conditional-content-persistence design, which carries
    // its own implementation plan rather than splitting into a second file.
    // One file, and one is the whole delta: `docs/design/` is not a published
    // page, so it gains no site mirror and costs this counter no second entry.
    // 170 -> 172: the vCon capture-stack page. `docs/vcon-harness.md` plus its
    // generated `website/content/docs/vcon-harness.md` -- two files, and two
    // is the whole delta, attributed by
    // `git diff --diff-filter=A HEAD -- '*.md'` before the number moved. It is
    // a published page, so unlike the entry above it does cost a second entry.
    // 172 -> 175 by three engineering notes. Three files and not six: notes
    // are written for the website directly and have no `docs/` source, so
    // they gain no generated mirror -- the same shape the 154 -> 157 entry
    // above records. Attributed with
    // `git diff --diff-filter=A ddb05f3a fa870e30` before the number moved.
    // 175 -> 177 by two more engineering notes, a how-to and a feature
    // writeup. Two files, and two is the whole delta for the reason the
    // 172 -> 175 entry gives: notes are written for the website directly
    // and have no `docs/` source to mirror.
    const EXPECTED_MARKDOWN_FILES: usize = 177;
    /// How many tables this gate expects to walk.
    ///
    /// Named rather than written twice. The count and the failure message
    /// used to be separate literals, and bumping the count left the message
    /// still naming the old number — so the gate that exists to catch a
    /// documentation value drifting from its source shipped exactly that.
    // Raised 604 -> 615 by the rtpengine pages. docs/rtpengine.md adds three
    // (method chooser, verification troubleshooting, the use-case set) and
    // docs/internals/rtpengine-control-plane.md adds two (module layout,
    // mutation results); both have generated mirrors, so ten. The eleventh is
    // the use-case table in docs/design/backlog.md, which has no mirror.
    // Attributed per file before the number moved.
    // Raised 615 -> 617 by the partial-export table in docs/examples.md
    // recipe 13, which maps each thing an exported WAV's note can say to what
    // happened and what to do about it. One table, doubled by the generated
    // cookbook mirror. Attributed per file before the number moved.
    // 617 -> 622: the five tables in the generated
    // `docs/design/testing-matrix.md` -- what each evidence tier claims,
    // the totals, and one table per surface (CLI flags, HTTP routes, MCP
    // tools). Attributed by measurement before the number moved: that file
    // holds exactly five and no other page gained one.
    // 622 -> 623: one table, the audited-verdict summary in the generated
    // `docs/design/testing-matrix.md`. It reports what a person found in the
    // 80 flags the generator could only call "referenced" -- 62 of them do
    // have a real behavior test, which a token search cannot see.
    // 623 -> 627: two hand-written tables and their two generated mirrors, both
    // about what a MOS is worth. `docs/mos-and-codecs.md` gained the per-surface
    // table (which door says a score is a placeholder, and how); `docs/rest-api.md`
    // gained the `mos_grounded`/`mos_grounding`/`mos_note` key table for
    // `GET /v1/streams`. `website/content/docs/{mos-and-codecs,api}.md` are the
    // generated copies. Attributed by measurement before the number moved: those
    // four files gained exactly one each and no other page gained any.
    // 627 -> 628: one table, in the generated `docs/design/testing-matrix.md`.
    // Its "what a tier claims" section described the CLI tiers only, while the
    // route and tool tables use two tiers of their own (`exercised`,
    // `defined only`) that the page never defined. Attributed by measurement
    // before the number moved: that file gained exactly one table separator and
    // no other page gained any, and design docs have no generated mirror.
    // 628 -> 634: three hand-written tables and their three generated mirrors,
    // all the same two-row table saying who asserted a stream's dialog --
    // `signaled` (a party's own SDP) against `media-relay` (an rtpengine relay
    // naming a port it allocated). One each in `docs/rtpengine.md`,
    // `docs/rest-api.md` and `docs/mcp-tools.md`, because the three readers
    // arrive at the fact from three different doors and none of them reads the
    // other two pages. Attributed by measurement before the number moved: those
    // six files gained exactly one table separator each and no other page
    // gained any.
    // 634 -> 638: two hand-written tables and their two generated mirrors, one
    // each in `docs/rest-api.md` and `docs/mcp-tools.md`, listing what the new
    // `caveats` block counts -- work sipnab DECLINED, as against the
    // `capture_quality` block beside it, which counts what the capture LOST.
    // Attributed by measurement before the number moved: those four files
    // gained exactly one table separator each and no other page gained any.
    // 638 -> 640: one hand-written table and its generated mirror, in
    // `docs/rest-api.md`, listing the four port-gate keys `/v1/stats` gained --
    // SIP and SIP-over-WebSocket the gate read, recognized and set aside, each
    // with the ports carrying it. Attributed by measurement before the number
    // moved: those two files gained exactly one table separator each and no
    // other page gained any.
    // 640 -> 641: one table, the four surface-parity gates and the bar each
    // holds, in the new SP section of `docs/design/backlog.md`. Attributed by
    // measurement before the number moved: that file gained exactly one table
    // separator, and design docs have no generated mirror.
    // 641 -> 644: three tables in the new `docs/design/vcon.md` -- the six
    // vCon decisions and the fact each turns on, the sipnab PARTIAL clause
    // against the vCon field that could carry it, and what is declined
    // outright. Attributed by measurement before the number moved: that file
    // holds exactly three table separators, no other page gained any (the
    // backlog's pointer is a row in a table that already existed), and design
    // docs have no generated mirror.
    // 644 -> 645: one table, the tagged VCON programme in
    // `docs/design/backlog.md` -- the ten items and their state. Attributed by
    // measurement before the number moved: that file gained exactly one table
    // separator and design docs have no generated mirror.
    // 645 -> 648: three tables. One hand-written and its generated mirror, in
    // `docs/mcp-tools.md` -- the `export_vcon` parameter table, which that
    // tool's new section needs like every other tool section on the page. One
    // more in `docs/design/vcon.md`, recording what a real vCon store measured
    // against what the draft says. Attributed by measurement before the number
    // moved: those three files gained exactly one table separator each, no
    // other page gained any, and design docs have no generated mirror.
    // 648 -> 650: one table and its generated mirror, in `docs/mcp-tools.md`
    // -- the four values `capture_completeness.media` can take, now that a
    // container may carry audio. The table exists because an absent
    // `recording` object has four quite different causes and an agent must not
    // have to infer which one from a missing key. Attributed by measurement
    // before the number moved: those two files gained exactly one table
    // separator each (47 -> 48), and no other page gained any.
    // 650 -> 664. Attributed per file by counting tables at `main` and here,
    // not by arithmetic on the gate's own number. `main` carries 643 and this
    // branch adds 21: the three new vCon pages (`docs/vcon.md` +4,
    // `docs/design/vcon.md` +4, `docs/internals/vcon.md` +2) and their site
    // mirrors (+4, +2), `docs/mcp-tools.md` +2 for the `export_vcon` rows and
    // its mirror +2, and `docs/design/backlog.md` +1 for the VCON backlog
    // table. 643 + 21 = 664; the 650 this replaces accounted for seven of them.
    // Then 664 -> 666 for the type-rule table `docs/vcon.md` gained when the
    // conserver interop audit changed how a Dialog Object is typed: one table
    // saying which `type` and `disposition` each kind of object carries, plus
    // its generated site mirror. Two files, one table each.
    // 666 -> 667: one table, in CONTRIBUTING.md, mapping each private-identity
    // class to what a writer should put instead. Attributed by measurement
    // before the number moved -- that file carried three table separators at
    // HEAD and carries four here, and no other page gained any. CONTRIBUTING.md
    // has no site mirror, so it costs one rather than two.
    // 671 -> 672: the generated status table at the top of backlog.md. One
    // table, in one file, attributed before this number moved.
    // 669 -> 671: one new table in docs/vcon.md naming the two fields that
    // report a deliberate absence, and its copy in the site mirror. Attributed
    // per file before this number was touched, because "fewer" is the alarm
    // this gate exists to raise.
    // 667 -> 669: two tables in the conditional-content-persistence design --
    // the precedence ladder, and the mutants Task 2 must die to. Attributed by
    // measurement: that file carries exactly two table separators and no other
    // page gained one. It is not a published page, so it costs no second entry
    // for a site mirror.
    // 692 -> 693: the REL1 closure in the backlog. One table, four rows, one
    // per external host the release build reaches -- netmap, libpcap,
    // bpf-linker and the apt archives -- recording how each is pinned,
    // verified and bounded. It is the whole evidence for the entry being
    // closed, so it is a table rather than prose: the claim is per-input and a
    // paragraph would let one of the four go unstated without looking wrong.
    // 672 -> 692: the vCon capture-stack page. Ten tables in
    // `docs/vcon-harness.md` and ten in its generated site mirror, counted
    // with `grep -c '^|---'` on each before the number moved. Twenty is the
    // whole delta, and a published page always costs this counter double.
    const EXPECTED_TABLES: usize = 693;

    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z", "*.md"])
        .current_dir(repo)
        .output()
        .expect("git ls-files");
    let files: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .collect();
    // Pinned. `>= 50` against a real 93 let the sweep lose nearly half the
    // tracked markdown without noticing, which for a duplicate-row check means
    // the duplicates it exists to find simply stop being looked for.
    // Raised 123 -> 124 by `docs/design/capture-tuning-tasks.md`, which two
    // tracked design docs already link to and so cannot stay untracked, and
    // 124 -> 125 by `website/content/docs/tuning-capture.md`, the site mirror
    // of the new tuning page.
    // 125 -> 127 by `CLA.md` (the Contributor License Agreement, also the gist
    // source) and `website/content/cla.md` (the sipnab.com/cla/ page).
    // Raised 130 -> 131 by `docs/design/icid-correlation.md`, the
    // P-Charging-Vector `icid-value` correlation spec. A design doc has no site
    // mirror, so it costs this counter one file and not two. The number is the
    // one this gate reported on a failing run, not one added up by hand.
    // Raised 131 -> 134 by the profiling work: docs/internals/profiling.md and
    // its site mirror (an internals page IS mirrored, so it costs two), plus
    // docs/design/packet-path-allocation.md, which is a design doc and costs
    // one. Also from a failing run.
    // Raised 148 -> 149 by `docs/design/documentation-pattern.md`, the record
    // of how prose docs are organized (split by task, depth in `<details>`).
    // A design doc, so one file and not two. Also from a failing run.
    // Raised 149 -> 153 by the MCP split: docs/mcp-walkthrough.md became
    // docs/mcp-deploy.md (a rename, no change), and docs/mcp.md shed its tool
    // reference and protocol contract into docs/mcp-tools.md and
    // docs/mcp-protocol.md. Two new operator pages, each mirrored, so four
    // files — and the page that was 3435 lines is now 112. Also from a
    // failing run.
    // Raised 153 -> 154 by docs/design/simultaneous-capture-sources.md, the
    // SRC1 design. One file, not two: a design doc has no website mirror. It
    // counts from the moment it is TRACKED rather than written, which is why
    // this fires at `git add` and not when the file appeared.
    // Raised 154 -> 157 by the engineering-notes section: website/content/
    // notes/_index.md and two posts. Three files and not six -- notes are
    // written for the website directly and have no docs/ source, which is the
    // mirror relationship inverted from every entry above.
    // Raised 157 -> 159 by splitting docs/mcp-deploy.md: the estate scenarios
    // (several SIP servers into one capture host, reaching it from outside,
    // many hosts under one agent, one call across an SBC and its PBXes) became
    // docs/mcp-estate.md. Two files and not one -- this page IS mirrored to the
    // site, unlike the notes above. mcp-deploy.md went 2386 -> 1840 lines.
    assert_eq!(
        files.len(),
        // Raised 159 -> 163 by the rtpengine pages: docs/rtpengine.md and
        // docs/internals/rtpengine-control-plane.md, each with its generated
        // website mirror. Two sources, two mirrors, attributed per file.
        //
        // The number was written twice, and raising it left the message still
        // naming 159 -- a gate reporting the wrong expectation to whoever it
        // fails next. One const now.
        EXPECTED_MARKDOWN_FILES,
        "found {} tracked markdown files, expected {EXPECTED_MARKDOWN_FILES}. \
         More is fine — bump \
         this. FEWER means the sweep stopped reading part of the tree and this \
         gate narrowed silently.",
        files.len()
    );

    let mut offenders = Vec::new();
    let mut tables = 0usize;
    for file in &files {
        let text = std::fs::read_to_string(repo.join(file)).unwrap_or_default();
        // Blank fenced blocks so an example that repeats a line is not a
        // finding, then walk consecutive `|` lines as one table.
        let scanned = markdown::blank_fences(&text);
        let lines: Vec<&str> = scanned.lines().collect();
        let mut table: Vec<(usize, &str)> = Vec::new();
        for (n, line) in lines
            .iter()
            .enumerate()
            .chain(std::iter::once((lines.len(), &"")))
        {
            let l = line.trim();
            if l.starts_with('|') {
                table.push((n + 1, l));
                continue;
            }
            if table.len() > 2 {
                tables += 1;
                for i in 0..table.len() {
                    // A separator row (`|---|---|`) legitimately repeats
                    // across tables but never within one.
                    if table[i].1.chars().all(|c| "|-: ".contains(c)) {
                        continue;
                    }
                    if let Some(j) = (0..i).find(|j| table[*j].1 == table[i].1) {
                        offenders.push(format!(
                            "{file}:{} duplicates line {}: {}",
                            table[i].0, table[j].0, table[i].1
                        ));
                    }
                }
            }
            table.clear();
        }
    }
    // Pinned. `>= 40` against a real 292 is the widest gap of the set: 250
    // tables could stop being walked and the gate would still report the
    // documentation as scanned.
    // Raised 437 -> 448 by the capture-tuning work, diffed file by file against
    // the merge base rather than guessed: `docs/tuning-capture.md` +4 and its
    // generated site mirror +4 (the same four pages twice, which is what a
    // mirrored page costs this counter),
    // `docs/design/process-isolation-and-hot-path-cost.md` +2 and
    // `docs/design/capture-tuning-tasks.md` +1. Nothing else moved: the pages
    // this cycle edited most heavily — `rest-api.md`, `mcp.md`,
    // `THIRD-PARTY-NOTICES.md` — grew ROWS inside tables that already existed,
    // which this gate does not count.
    // Raised 448 -> 454 by `docs/encapsulations.md`, counted rather than
    // guessed: three tables on the page (link types, EtherTypes, tunnels above
    // the link layer) and three in its generated site mirror — the same page
    // twice, which is what a mirrored page costs this counter, exactly as the
    // tuning-capture entry above records.
    // Raised 454 -> 460 by the `capture_health` MCP tool, counted rather than
    // guessed: three tables in its `docs/mcp.md` section (the parameter, the
    // `attachment` codes, the `undecodable_by_reason` codes) and three in the
    // generated site mirror — the same page twice, which is what a mirrored
    // page costs this counter, exactly as the two entries above record. The
    // tool-table row it also adds grew a table that already existed, which
    // this gate does not count.
    // Raised 460 -> 462 by the "three shapes" table in
    // `docs/mcp-deploy.md`, counted rather than guessed: one table there
    // and one in the generated site mirror — the same page twice, which is what
    // a mirrored page costs this counter, exactly as the entries above record.
    // It replaced a bullet list with a table so each shape could link to the
    // section that documents it, which is why this is +2 and not +1 per shape.
    // Raised 462 -> 464 by the four-strategy correlation table in
    // `docs/internals/domain-primer.md`: one table there and one in the
    // generated site mirror, the same page twice, as the entries above record.
    // Raised 464 -> 466 by `find_correlated`'s strategy table in docs/mcp.md:
    // one there and one in the site mirror, the same page twice.
    // Raised 466 -> 470 by the federated-tracing section in
    // docs/mcp-deploy.md: a strategy table and a federated-vs-centralised
    // table, each doubled by the site mirror.
    // Raised 470 -> 472 by the untrusted-capture-text section in docs/mcp.md
    // (#139): one fenced/verbatim table per surface, doubled by the site mirror.
    // Raised 472 -> 474 by the write-verb table in docs/mcp.md's "What the
    // write verbs do" section (#146): one table plus the site mirror.
    // Raised 475 -> 477 by the `show_evidence` status table (one per doc
    // mirror), which spells out that verified / unverified / unresolvable are
    // three different claims rather than degrees of the same one.
    // Raised 474 -> 475 by the "What shipped" table added to §2 of
    // docs/design/deferred-and-declined.md, which had been describing
    // save_findings and CaptureEtag as pending after both had shipped. That
    // page has no site mirror, so it counts once.
    //
    // The three entries above landed on two branches that were merged: the
    // first two on main, the third on the stale-documentation sweep. Neither
    // side's total was right for the merged tree, so this number was taken
    // from a clean run rather than added up.
    // Raised 479 -> 487 by the three design specs (live-fanout, syscall-sandbox,
    // mid-dialog-state-machine). Previously raised 477 -> 479 by the "I want to"
    // goal index added to the top of
    // docs/install.md, which the project's own task-first rule requires of
    // every how-to page. That page HAS a site mirror, so one authored table
    // counts twice.
    // Raised 487 -> 493 by the B2BUA-correlation and scripted-client work in
    // docs/mcp-deploy.md, taken from this gate's own count rather than
    // added up: three NEW tables (the four fields to read off `find_correlated`,
    // which responses carry `capture_identity`, and the HTTP-status decoder for
    // the script), each doubled by the site mirror. The strategy table on that
    // page grew a `via_branch` row and a fourth column, which is growth inside a
    // table that already existed and so does not count here.
    //
    // Raised again by docs/design/icid-correlation.md, the P-Charging-Vector
    // `icid-value` correlation spec: eight authored tables on one page (the five
    // existing strategies, the RFCs updating RFC 7315, what a plain icid match
    // means per hop, where the header is present per hop, the two proposed
    // reasons, the parameters that must never be surfaced, the files a new
    // strategy touches, and how a fixture denies each existing strategy). A
    // design doc has no site mirror, so each counts ONCE — unlike the mirrored
    // pages above, which cost two apiece.
    //
    // Those two landed on separate branches, and neither side's total was right
    // for the merged tree. As with the 479 entry above, this number was taken
    // from a clean run of this gate rather than added up.
    //
    // Raised 501 -> 502 by the 0.5.88 changelog entry, which tabulates the two
    // `P-Charging-Vector` strategies against what a match on each one actually
    // claims. CHANGELOG.md is walked by this gate and has no site mirror, so it
    // costs one. Worth knowing before writing a release entry: a table in the
    // changelog moves this ratchet exactly like a table in a doc page does.
    // Raised 502 -> 503 by PERF1's measurement table in docs/design/backlog.md,
    // which tabulates four builds against the throughput each one measured.
    // Same rule as the changelog entry above: that file is walked by this gate
    // and has no site mirror, so a table there costs one rather than two.
    // Raised 503 -> 504 by PERF1's bisect table, which records what each
    // commit measured with the digest zeroed. Same rule as the two entries
    // above: backlog.md has no site mirror, so a table there costs one.
    // Raised 504 -> 509 by the profiling work: the tool-selection table in
    // docs/internals/profiling.md, doubled by its site mirror, plus three in
    // docs/design/packet-path-allocation.md (the symbol profile, the driver
    // attribution, the targets) which count once because a design doc has no
    // mirror.
    // Raised 509 -> 510 by the measured-ceilings table in
    // docs/design/packet-path-allocation.md. A design doc has no site mirror,
    // so it costs one.
    // Raised 510 -> 511 by the consumer table in P1's blocker analysis
    // (docs/design/packet-path-allocation.md). Design doc, no mirror, costs one.
    // Raised 511 -> 512 by P2's measurement table in
    // docs/design/packet-path-allocation.md. Design doc, no mirror, costs one.
    // Raised 512 -> 513 by the 0.5.91 changelog's throughput table.
    // CHANGELOG.md is walked by this gate and has no site mirror, so it
    // costs one.
    // Raised 513 -> 514 by the surface-comparison table in
    // docs/design/i18n.md. Design doc, no mirror, costs one.
    // Raised 514 -> 516 by docs/design/positioning.md, which carries two: the
    // gap comparison and the verified-capability inventory. Design doc, no
    // mirror, so it costs two rather than four.
    //
    // LOWERED 516 -> 512 on 2026-08-10, which this gate normally treats as
    // suspicious and is not here: the tool-comparison tables were REMOVED from
    // both benchmarks copies (a head-to-head table and a memory table in each,
    // four in total). sipnab is not positioned against those tools -- see
    // docs/design/positioning.md -- and the pages now state what sipnab
    // reconstructs rather than how it ranks. If this count drops again without
    // a deletion named here, the detection broke.
    //
    // LOWERED 512 -> 494 on 2026-08-10, and again this is a repair rather than
    // a loss. Twelve rows in sip-header-fields.md were split across two lines
    // by the IANA-registry scrape; each break ENDED its table and the next row
    // opened a new one, so a single 136-row table was being walked as
    // fourteen. It is now two -- compact forms, and all header fields -- in
    // docs/ and in the site mirror, which is the 12 + 10 that disappeared.
    // Attributed per file before this number was touched, because "fewer" is
    // exactly the alarm this gate exists to raise.
    assert_eq!(
        // Raised 494 -> 496 by the new [media] config section: one table in
        // docs/config-reference.md and one in its site mirror.
        // Raised 496 -> 498: docs/auth.md gained two tables in the scoped-token
        // rewrite, and docs/mcp.md one. Attributed per file before the number
        // moved — every changed page was diffed against HEAD and each delta is
        // a table that was written, not a boundary that stopped being detected.
        // Raised 498 -> 502 by the threshold-wiring keys: a new `[diagnosis]`
        // table in docs/config-reference.md and a new "Diagnosis thresholds"
        // table in docs/cli-reference.md, each mirrored once under
        // website/content/docs/. Two written tables, four pages, and every
        // other page diffed against HEAD to confirm no boundary was lost.
        // Raised 502 -> 504 by the round-trip work: docs/rest-api.md gained a
        // table naming the two sources a latency figure can come from
        // (`xr_voip_metrics` vs `sender_report_echo`), and its site mirror
        // carries the same one. Attributed per file against HEAD before this
        // number moved — six .md files changed, and exactly two of them gained
        // a table.
        // Raised 504 -> 505 by the 0.5.96 CHANGELOG entry, which carries the
        // same round-trip source table the REST reference does — a reader
        // deciding whether to upgrade needs to know `sender_report_echo` is a
        // lower bound on most topologies, not just that latency "works now".
        // One file, one table, diffed against HEAD before the number moved.
        // Raised 505 -> 509 by the quality color bands, which take the same
        // shape the `[diagnosis]` wiring did at 498 -> 502: a new `[quality]`
        // table in docs/config-reference.md and a new "Quality color bands"
        // table in docs/cli-reference.md, each mirrored once under
        // website/content/docs/. Two written tables, four pages. Every staged
        // .md was diffed against HEAD first: exactly those four gained one
        // separator row each, and README.md and docs/design/backlog.md — both
        // also staged — held their table counts, so nothing here is a boundary
        // that stopped being detected.
        // Raised 509 -> 523 by the MCP tool-reference rewrite, which made every
        // parameter of every tool answerable: what it is, what values are
        // legal, what the tool does when you omit it, and what comes back.
        // Attributed per file against HEAD before this number moved. Exactly
        // two .md files changed — docs/mcp.md and its site mirror — and each
        // gained SEVEN tables, which is the +14:
        //   * FIVE parameter tables for tools that previously documented no
        //     parameters at all (find_correlated, show_evidence, export_audio,
        //     shutdown_server, save_findings). Every one of them accepts
        //     arguments the page never named.
        //   * ONE `Returns` table for get_dialog, whose five response fields
        //     had been a single prose sentence.
        //   * ONE table under "Response bounding" naming the four tools that do
        //     NOT report a total_matched, because the paragraph above it
        //     claimed every list-style tool does and two of them return a bare
        //     array with no total, no truncation flag and no cursor.
        // The other 14 parameter tables on the page grew from three columns to
        // four (`Legal values` and `If omitted` replacing `Description`), which
        // is growth inside a table that already existed and so does not count
        // here — the same rule the capture_health entry above records.
        // Raised 523 -> 527 by #113, which gave `search_messages` and
        // `security_findings` page objects: each gained ONE `Returns` table
        // documenting fields that had been prose, doubled by the site mirror
        // (2 tables x 2 pages). Attributed per file against HEAD before this
        // number moved — every other .md this change touched
        // (`docs/rest-api.md`, `docs/filter-dsl.md`,
        // `docs/mcp-deploy.md`, `CHANGELOG.md`, and their mirrors) held
        // its table count. The "Four tools are exceptions" table in
        // `docs/mcp.md` lost two ROWS and stayed a table, which this gate does
        // not count either way.
        // Raised 527 -> 528 by the syscall-sandbox posture table: §0 of
        // docs/design/syscall-sandbox.md now tabulates the hardening that IS
        // in place against what each control does not stop, so the page stops
        // reading as "sipnab runs unhardened". ONE table, and one page —
        // docs/design/ is deliberately not published to the wiki or the site
        // (scripts/build-wiki.py), so there is no mirror to double it.
        // Attributed against HEAD before the number moved: both staged .md
        // files were diffed, and exactly one `|---|` separator was added.
        // docs/design/backlog.md gained prose in the G5 entry and held its
        // table count, so nothing here is a boundary that stopped matching.
        // Raised 528 -> 532 by the `media_diagnostics` section: its parameter
        // table and its five-block table, each doubled by the site mirror.
        // Attributed per file against HEAD before the number moved — the two
        // separators are in docs/mcp.md and the two matching ones in
        // website/content/docs/mcp.md, which scripts/build-site-pages.py
        // regenerates. No other page changed a table boundary.
        // Raised 532 -> 534 by the `mos_grounding` table in docs/mcp.md, which
        // `[media.codec_ie]` made necessary: "grounded" now covers a published
        // G.113 value AND an operator-declared one, and a bare boolean cannot
        // say which. ONE table, doubled by the site mirror. The two increments
        // landed in separate branches, each correctly recording +4 and +2
        // against 528; merged, both apply.
        // Raised 535 -> 539 on 2026-08-15 by the aarch64 benchmark baseline in
        // benches/BASELINES.md: four tables, one per section (parser,
        // detection/decap, packet path and stores, TUI derived state). Not
        // mirrored to the site, so four and not eight.
        // Raised 534 -> 535 on 2026-08-14 by ONE table in docs/design/backlog.md:
        // the `TK` section's comparison of what sngrep's eBPF commits changed
        // against what sipnab already does, so neither is rebuilt by mistake.
        // Not doubled by a site mirror — docs/design/ is not published.
        // Raised 573 -> 575 by the STUN/SDP evidence table in
        // docs/output-formats.md — the field-by-field reading of
        // `diagnosis.stun_sdp_mismatch` — doubled by its site mirror. ONE
        // written table, two pages.
        //
        // Raised 575 -> 577 by the "what STUN shows / what it means" table in
        // docs/troubleshooting.md, under "The SDP offered a private address".
        // Same arithmetic: one written table, doubled by its site mirror. It
        // replaced the claim that sipnab "cannot tell those apart from one
        // capture", which the STUN evidence made false.
        //
        // Raised 577 -> 579 by the two tables in
        // docs/design/documentation-pattern.md — the four page kinds, and the
        // MCP split. A design doc, so no site mirror doubles them; two written
        // tables, two counted. Worth noting for the next person: this gate
        // walks TRACKED files, so a new page's tables do not appear in the
        // count until it is `git add`ed, and a standalone run before staging
        // will pass while the pre-commit hook fails.
        // Every other changed .md was diffed against
        // HEAD first: cli-reference.md, prometheus-metrics.md and
        // troubleshooting.md gained rows and prose inside EXISTING tables, and
        // held their table counts.
        //
        // Raised 579 -> 581 by the ICE work: ONE written table, the fields of
        // the `--json-stun` `ice` record in docs/output-formats.md, doubled by
        // its site mirror. Attributed per file before the number moved:
        // prometheus-metrics.md and its mirror gained two ROWS in the existing
        // metrics table, and troubleshooting.md gained two prose sections with
        // no table in either, so all three held their counts.
        tables,
        // Raised 581 -> 583 by the two tables in
        // docs/design/simultaneous-capture-sources.md, the SRC1 design: one
        // mapping each capture source to what it can and cannot supply, and
        // one for the staged plan. A design doc has no site mirror, so two
        // tables and not four. Attributed against that file alone.
        //
        // Raised 583 -> 587 by two tables that DO have mirrors, so four:
        // docs/examples.md gained the kernel-buffer vs interface/driver
        // comparison in "Measure whether the loss is yours or the network's",
        // and docs/tuning-capture.md gained "Where the two numbers appear",
        // listing the four surfaces that report the same pair. The cookbook's
        // navigation table gained fourteen ROWS for the new recipes and is
        // still one table, so it does not move this count.
        //
        // Raised 587 -> 589 by two more tables in
        // docs/design/simultaneous-capture-sources.md when SRC1 stage 1
        // shipped: the F1 measurement (advertised vs observed media endpoints,
        // per tracer scope and topology) and the map from each test the design
        // asked for to the name it shipped under. A design doc has no site
        // mirror, so two and not four. Attributed per file against HEAD:
        // docs/examples.md gained recipe 6d and docs/cli-reference.md a
        // rewritten `--hep-listen` row, both PROSE and rows inside an existing
        // table, so both held their counts along with their mirrors.
        //
        // Raised 589 -> 590 by the PR1 before/after throughput table in the
        // 0.5.119 CHANGELOG entry. One table and not two: CHANGELOG.md has no
        // site mirror. It is a table rather than prose because the two- and
        // four-core rows are a REGRESSION, and a reader owed that number is
        // owed it beside the rows it is being traded against.
        //
        // Raised 590 -> 591 by SRC1 stage 2: the design-test-to-name table in
        // the stage-2 section of docs/design/simultaneous-capture-sources.md,
        // matching the one stage 1 already carries. One and not two — a design
        // doc has no site mirror. Attributed per file against HEAD:
        // docs/design/live-fanout.md gained a §2.3 of PROSE and every other
        // changed page only moved line anchors inside existing tables, so all
        // of those held their counts.
        //
        // Raised 591 -> 596 by the documentation sweep that followed the
        // 0.5.118 throughput regression. Five tables, attributed per file:
        // the late-keylog hold bounds in docs/tls-capture.md and its site
        // mirror, the mirror-vs-wire finding table in docs/examples.md and the
        // cookbook generated from it, and the answer-surface table in
        // docs/architecture.md, which has no site mirror.
        //
        // Raised 596 -> 597 by the release-comparison table in the engineering
        // note on the 0.5.118 regression. One and not two: a note is written
        // for the website directly and has no docs/ source to mirror.
        //
        // Raised 597 -> 599 by MCPX5's `get_capture_report`: its parameter
        // table in docs/mcp-tools.md, doubled by the generated site mirror.
        //
        // Raised 599 -> 601 by MCPX2's `aggregate_dialogs`, the same way: one
        // parameter table, doubled by the mirror.
        //
        // Raised 601 -> 603 by the response-class table in docs/filter-dsl.md,
        // which lists the six IANA classes against both the number and the
        // registry's own name. Doubled by the generated site mirror.
        // Raised 603 -> 604 by the worked-examples table in docs/library.md,
        // which lists the three programs in examples/ against what each one
        // demonstrates. One table, one file, no site mirror: library.md has
        // no site counterpart. Attributed per file before the number moved.
        EXPECTED_TABLES,
        "walked {tables} tables, expected {EXPECTED_TABLES}. More is fine — bump \
         this. FEWER means the table detection stopped matching and this gate is \
         checking less than it claims."
    );
    assert!(
        offenders.is_empty(),
        "documentation tables repeat a row — either a copy-paste artifact, or a \
         key that dropped the column telling the rows apart:\n  {}",
        offenders.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Task-first headings (spec: docs/design/task-first-docs.md)
// ---------------------------------------------------------------------------

/// How-to headings must name the reader's goal, and the ratio may not fall.
///
/// A user looking for "sipnab on a remote server, Claude Code on my laptop"
/// could not find it, because the section was called "Scenario 2A —
/// SSH-launched stdio: ad-hoc, zero server configuration". Accurate, and
/// useless to anyone who did not already know that "SSH-launched stdio" was the
/// thing they wanted. Measured across the three how-to pages, task-first
/// headings ran 90% / 62% / 8% — so the repo knew how to do this everywhere
/// except the newest surface, whose docs were written from the implementation
/// outward.
///
/// A **ratchet, not a threshold**, and deliberately so. Some headings are
/// legitimately nouns — "Codex CLI", "Cursor", "VS Code" are a list of clients,
/// not tasks — so no honest fixed percentage exists. What must not happen is
/// backsliding, and that is exactly what a floor per page catches.
///
/// Raising a floor after improving a page is the intended workflow. Lowering
/// one is the thing to argue about in review.
#[test]
fn how_to_headings_stay_task_first() {
    /// Verbs a reader would use for their own goal. Extend freely — a missing
    /// verb only ever understates the score, which the ratchet tolerates.
    const GOAL_VERBS: &[&str] = &[
        "alert",
        "analyze",
        "analyze",
        "ask",
        "block",
        "browse",
        "check",
        "choose",
        "collect",
        "compare",
        "configure",
        "connect",
        "decrypt",
        "detect",
        "diagnose",
        "drive",
        "exchange",
        "export",
        "feed",
        "filter",
        "find",
        "fix",
        "follow",
        "generate",
        "graph",
        "inspect",
        "install",
        "keep",
        "listen",
        "live",
        "look",
        "measure",
        "narrow",
        "open",
        "query",
        "reach",
        "read",
        "record",
        "register",
        "run",
        "save",
        "search",
        "send",
        "set",
        "stream",
        "test",
        "trace",
        "triage",
        "understand",
        "use",
        "verify",
        "watch",
        "wire",
    ];

    // (page, floor) — the measured ratio at the time of writing, as a percent.
    const PAGES: &[(&str, usize)] = &[
        ("docs/tui-walkthrough.md", 90),
        ("docs/mcp-deploy.md", 64),
        ("docs/examples.md", 93),
    ];

    let strip = regex::Regex::new(
        r"(?i)^(\d+[a-z]?\.\s*|Scenario\s+\d+[A-Z]?\s*[—-]\s*|Step\s+\d+\s*[—-]\s*)",
    )
    .unwrap();
    let heading = regex::Regex::new(r"(?m)^#{2,3}[ \t]+(.+?)[ \t#]*$").unwrap();

    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (page, floor) in PAGES {
        let text =
            std::fs::read_to_string(repo.join(page)).unwrap_or_else(|e| panic!("read {page}: {e}"));
        let heads: Vec<String> = heading
            .captures_iter(&markdown::prose(&text))
            .map(|c| c[1].to_string())
            .collect();
        assert!(
            !heads.is_empty(),
            "{page}: no headings found — did the page move?"
        );

        let task_first = heads
            .iter()
            .filter(|h| {
                let core = strip.replace(h, "");
                core.split_whitespace()
                    .next()
                    .map(|w| {
                        let w = w.to_lowercase();
                        let w = w.trim_end_matches([':', ',']);
                        GOAL_VERBS.contains(&w)
                    })
                    .unwrap_or(false)
            })
            .count();
        let pct = task_first * 100 / heads.len();

        assert!(
            pct >= *floor,
            "{page}: {task_first}/{} headings are task-first ({pct}%), below the \
             {floor}% floor. A how-to heading names the reader's GOAL, not the \
             mechanism — \"Connect Claude Code on your laptop to sipnab on a \
             server\", not \"SSH-launched stdio\". Put the mechanism in a \
             subtitle underneath. If you genuinely improved the page, raise the \
             floor; lowering it needs an argument.",
            heads.len()
        );
    }
}

/// Omitting `-d` must be documented as platform-dependent, not "auto-detect".
///
/// On Linux the default is the `any` pseudo-device — **every** interface at
/// once, loopback included. On macOS/BSD it is libpcap's default: exactly
/// **one** interface. The reference previously said "auto-detects the default
/// interface", which reads as one interface everywhere and is wrong on Linux
/// in the direction that matters: a reader concludes they are missing loopback
/// when they are not, or on macOS that they are covered when they are not.
///
/// Both trees, because a reader lands on either.
#[test]
fn device_default_is_documented_per_platform() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for page in ["docs/cli-reference.md", "website/content/docs/cli.md"] {
        let text =
            std::fs::read_to_string(repo.join(page)).unwrap_or_else(|e| panic!("read {page}: {e}"));
        assert!(
            text.contains("`any` pseudo-device"),
            "{page}: must name the Linux default as the `any` pseudo-device"
        );
        assert!(
            text.contains("every interface at once"),
            "{page}: must say the Linux default covers every interface — \
             \"auto-detect\" reads as one"
        );
        assert!(
            text.contains("one interface"),
            "{page}: must say macOS/BSD gets a single interface, or a mac \
             reader assumes the Linux behavior"
        );
        assert!(
            !text.contains("Auto-detects the default interface"),
            "{page}: the old wording is back — it is wrong on Linux"
        );
    }

    // The CLI help is where most people actually look.
    let cli = std::fs::read_to_string(repo.join("src/cli.rs")).expect("read cli.rs");
    assert!(
        cli.contains("ALL interfaces at once"),
        "src/cli.rs: -d help must state the Linux default captures all interfaces"
    );
}

/// The SIP parameter tables must stay consistent with what sipnab claims.
///
/// `docs/sip-parameters.md` is built from three IANA registries and carries a
/// "sipnab parses" column. Two ways that page can lie, and this covers both.
///
/// The first draft computed the column by grepping the source for each
/// parameter name and reported 41 of 204 — wrong and flattering, because `m`,
/// `code`, `alg` and `count` all occur in unrelated code. A substring match is
/// not evidence of parsing. The page now claims only what could be traced to a
/// real extraction site, and this test holds those three to their accessors:
/// if `top_via_branch` or `from_tag` were removed, the claim becomes false and
/// the build fails rather than the docs quietly overstating.
#[test]
fn sip_parameter_claims_match_the_parser() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(repo.join("docs/sip-parameters.md"))
        .expect("read docs/sip-parameters.md");
    let msg = std::fs::read_to_string(repo.join("src/sip/message.rs")).expect("read message.rs");
    let diag =
        std::fs::read_to_string(repo.join("src/sip/diagnosis.rs")).expect("read diagnosis.rs");

    // (parameter, the accessor that justifies the claim, where it lives)
    for (param, accessor, source) in [
        ("branch", "fn top_via_branch", &msg),
        ("tag", "fn from_tag", &msg),
        ("expires", "fn expiry_of", &diag),
    ] {
        assert!(
            source.contains(accessor),
            "docs/sip-parameters.md claims sipnab parses `{param}`, but \
             `{accessor}` is gone. Either restore it or drop the claim — an \
             overstated support table sends someone looking for a field that \
             is not there."
        );
    }

    // The conservative-by-construction note must survive, because the number
    // is the part a future editor is most likely to "improve" back into a grep.
    assert!(
        page.contains("substring match is not evidence of parsing"),
        "the page must keep explaining why the support column is hand-verified; \
         without it, someone recomputes it by grep and reinflates it"
    );

    // Registry sizes, pinned. A drop means the build script stopped reading a
    // registry and the page silently shrank.
    for (heading, min) in [
        ("## SIP/SIPS URI parameters (", 30),
        ("## Header field parameters (", 190),
        ("## Option tags (", 30),
    ] {
        let at = page
            .find(heading)
            .unwrap_or_else(|| panic!("missing section: {heading}"));
        let rest = &page[at + heading.len()..];
        let n: usize = rest
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        assert!(
            n >= min,
            "{heading}{n}) is below {min} — a registry probably failed to load \
             and the table shipped short"
        );
    }
}

/// Every registered MCP tool needs its own documented section with an example.
///
/// A sibling test already checks the tool TABLE lists every tool. That is an
/// index, not documentation, and the gap it left was real: `triage_call`,
/// `search_by_time`, `list_captures`, `export_capture` and `export_audio` all
/// shipped with a table row and no section. The table gate was green
/// throughout, which is why nobody noticed — a reader could see that a tool
/// existed and nothing about how to call it or how to read its answer.
///
/// So this gate asks for the two things a row cannot give: a heading naming the
/// tool, and a concrete example under it.
#[test]
fn every_mcp_tool_has_a_documented_section_with_an_example() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let server =
        std::fs::read_to_string(repo.join("src/mcp/server.rs")).expect("read src/mcp/server.rs");
    let page =
        std::fs::read_to_string(repo.join("docs/mcp-tools.md")).expect("read docs/mcp-tools.md");

    let name_re = regex::Regex::new(r#"name\s*=\s*"([a-z_]+)""#).unwrap();
    let tools: std::collections::BTreeSet<String> = name_re
        .captures_iter(&server)
        .map(|c| c[1].to_string())
        .collect();
    assert!(
        tools.len() >= 20,
        "found only {} registered tools — the attribute shape changed and this \
         gate is no longer reading the registry",
        tools.len()
    );

    // Split the page into h3 sections so an example can be attributed to the
    // tool whose heading it sits under, rather than merely existing somewhere.
    let heads: Vec<(usize, String)> = page
        .match_indices("\n### ")
        .map(|(i, _)| {
            let start = i + 1;
            let end = page[start..].find('\n').map_or(page.len(), |n| start + n);
            (start, page[start..end].to_string())
        })
        .collect();

    let mut missing_section = Vec::new();
    let mut missing_example = Vec::new();

    for tool in &tools {
        let needle = format!("`{tool}`");
        let Some(idx) = heads.iter().position(|(_, h)| h.contains(&needle)) else {
            missing_section.push(tool.clone());
            continue;
        };
        let body_start = heads[idx].0;
        let body_end = heads.get(idx + 1).map_or(page.len(), |(next, _)| *next);
        let body = &page[body_start..body_end];
        // A fenced block under the heading: the call, its response, or both.
        if !body.contains("```") {
            missing_example.push(tool.clone());
        }
    }

    assert!(
        missing_section.is_empty(),
        "these MCP tools have no `### ` section in docs/mcp-tools.md: {missing_section:?}. \
         A table row says a tool exists; it does not say how to call it or how to \
         read the answer. Give each one a heading naming it."
    );
    assert!(
        missing_example.is_empty(),
        "these MCP tools have a section but no fenced example: {missing_example:?}. \
         Show real output — an operator reaching for a tool mid-incident needs to \
         recognize the answer, not infer its shape."
    );
}

/// Every AMR-WB number printed in `docs/mos-and-codecs.md` must match the model.
///
/// Both columns are checked against `emodel_wb`, because both were wrong when
/// first written. The `Ie,WB` values were transcribed correctly from G.113, and
/// then five of the fifteen MOS figures beside them were computed by hand and
/// rounded wrong — 19.85, 18.25 and 8.85 monotic, 15.85 and 12.65 diotic. The
/// error was small enough to read as plausible and is exactly what this page
/// exists to warn against, so the page is now derived-checked rather than
/// trusted.
#[test]
fn the_published_amr_wb_tables_match_the_model() {
    /// AMR-WB rows the codec table is expected to carry.
    ///
    /// 15: the nine AMR-WB modes plus the six bandwidth-extension rows the
    /// model derives. It has never moved, and if it does, name what changed --
    /// a codec table that shrinks silently is a table that stopped covering
    /// modes the model still scores.
    const EXPECTED_AMR_WB_ROWS: usize = 15;
    use sipnab::rtp::emodel_wb::{ListeningContext, amr_wb_ie, amr_wb_mos};

    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(repo.join("docs/mos-and-codecs.md"))
        .expect("read docs/mos-and-codecs.md");

    // Rows look like: | 12.65 | 13 | 4.34 |
    let row = regex::Regex::new(r"(?m)^\| ([0-9.]+) \| ([0-9]+) \| ([0-9.]+) \|$").unwrap();

    // The monotic table is the first of the two; split on its heading so a row
    // is attributed to the right listening context.
    let split = page
        .find("### Diotic")
        .expect("the diotic heading anchors the split");
    let sections = [
        (&page[..split], ListeningContext::Monotic),
        (&page[split..], ListeningContext::Diotic),
    ];

    let mut checked = 0;
    for (text, context) in sections {
        for c in row.captures_iter(text) {
            let kbps: f64 = c[1].parse().expect("kbit/s");
            let ie: f64 = c[2].parse().expect("Ie,WB");
            let mos: f64 = c[3].parse().expect("MOS");

            let real_ie = amr_wb_ie(kbps, context).unwrap_or_else(|| {
                panic!("docs list {kbps} kbit/s for {context:?}, the model has no such row")
            });
            assert!(
                (real_ie - ie).abs() < f64::EPSILON,
                "{kbps} kbit/s {context:?}: docs say Ie,WB={ie}, model says {real_ie}"
            );

            let real_mos = amr_wb_mos(kbps, context, 0.0).expect("scorable at zero loss");
            assert!(
                (real_mos - mos).abs() < 5e-3,
                "{kbps} kbit/s {context:?}: docs say MOS={mos}, model says \
                 {real_mos:.6} (rounds to {real_mos:.2})"
            );
            checked += 1;
        }
    }

    // Nine monotic rows plus six diotic. Fewer means the regex stopped matching
    // the table and this gate silently checked nothing.
    assert_eq!(
        checked, EXPECTED_AMR_WB_ROWS,
        "expected {EXPECTED_AMR_WB_ROWS} AMR-WB rows in docs/mos-and-codecs.md, \
         matched {checked}. \
         More is fine — bump this. FEWER means the table shape changed and the \
         gate is no longer reading it."
    );
}

/// Every alias the documentation spells out in full must expand to exactly what
/// `expand_alias` returns.
///
/// `problems` is the one alias documented verbatim, in `docs/examples.md` and
/// its site mirror `website/content/docs/cookbook.md`. That makes the quoted
/// expansion load-bearing, and it had drifted: both files
/// listed `OR rtp.orphaned == true`, a field withdrawn from the DSL, so the
/// docs promised a broader sweep than the code performs AND named a field that
/// `--filter` now refuses outright.
///
/// Nothing caught it. `rtp_orphaned_is_refused_with_a_reason` in `src/sip/dsl.rs`
/// pins the refusal and `expand_alias`'s own test pins that the alias does not
/// contain "orphaned", but neither reads the documentation. This does.
#[test]
fn a_documented_alias_expands_to_what_the_code_expands_it_to() {
    let want =
        sipnab::sip::dsl::expand_alias("problems", &sipnab::sip::dsl::AliasThresholds::default())
            .expect("the problems alias exists");
    let normalize = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let want = normalize(&want);

    let mut checked = 0;
    for rel in ["docs/examples.md", "website/content/docs/cookbook.md"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));

        // The expansion is quoted in backticks and is the only backticked span
        // in these files that opens with the alias's first predicate.
        let opener = want
            .split(" OR ")
            .next()
            .expect("the expansion has at least one predicate");
        let found = text
            .split('`')
            .find(|span| span.trim_start().starts_with(opener))
            .unwrap_or_else(|| {
                panic!(
                    "{rel} no longer quotes the `problems` expansion (nothing \
                     backticked starts with {opener:?}). If the documentation \
                     stopped spelling the alias out, delete this gate rather \
                     than letting it pass by finding nothing."
                )
            });

        assert_eq!(
            normalize(found),
            want,
            "{rel} documents the `problems` alias as expanding differently from \
             `expand_alias`. A reader building on the quoted expression gets a \
             different set of dialogs than `--filter problems` returns."
        );
        checked += 1;
    }

    assert_eq!(checked, 2, "both the doc and its site mirror must be read");
}

/// The benchmarks page names ONE measured release, and says so consistently.
///
/// This gate exists because a version bump broke it and nothing noticed. The
/// 0.5.105 bump ran a blanket `sipnab 0.5.104 (` -> `sipnab 0.5.105 (` sweep
/// across the docs to move the `--version` examples, and the benchmarks page
/// carries a line in exactly that shape:
///
/// ```text
/// - **Version:** sipnab 0.5.104 (release artifact). **Date:** 2026-08-17.
/// ```
///
/// So the page shipped claiming its tables came from a release that had not
/// existed when they were measured, while its own header still named the real
/// one. Every other version marker in this repo tracks the crate or the last
/// published release; this one tracks NEITHER. It records what a measurement
/// was taken against, which is a historical fact that a later release does not
/// change — the same reason the A/B table keeps its own date.
///
/// Asserts the page agrees with itself rather than with `Cargo.toml`, so the
/// gate stays right when the crate moves on and fails when a sweep drags this
/// line along with it.
#[test]
fn the_benchmarks_page_names_one_measured_release_throughout() {
    let pages = [
        ("docs/benchmarks.md", include_str!("../docs/benchmarks.md")),
        (
            "website/content/docs/benchmarks.md",
            include_str!("../website/content/docs/benchmarks.md"),
        ),
    ];
    let ver = regex::Regex::new(r"(\d+\.\d+\.\d+)").unwrap();
    for (name, doc) in pages {
        // Every sentence that states what was measured, by the phrasing each
        // copy actually uses.
        let claims: Vec<String> = doc
            .lines()
            .filter(|l| {
                l.contains("comes from one run")
                    || l.starts_with("on 0.5.")
                    || l.contains("Measured against")
                    || l.contains("Measured on the released")
                    || l.contains("Taken on the released")
                    || l.contains("**Version:** sipnab")
            })
            .filter_map(|l| ver.captures(l).map(|c| c[1].to_string()))
            .collect();
        assert!(
            claims.len() >= 2,
            "{name}: found {} version claim(s); the page must state the release \
             it measured in its header AND in its method block, or this gate is \
             checking nothing",
            claims.len()
        );
        let first = &claims[0];
        assert!(
            claims.iter().all(|c| c == first),
            "{name}: the page names more than one measured release {claims:?}. \
             A blanket version bump most likely dragged `**Version:** sipnab X` \
             along with the `--version` examples. This line records what the \
             tables were measured against, which a later release does not change."
        );
    }
}

/// The MCP tool count in prose must match what the server registers.
///
/// `homepage_mcp_tool_tile_matches_the_server` in `site_journey_test` already
/// derives this count and holds the homepage tile to it. It stops at the
/// homepage, and the README and the design notes drifted behind it unnoticed:
/// both said 31 while the server registered 35, so the most-read file in the
/// repository undercounted the surface by four tools. Deriving the number in
/// one gate and hand-writing it in three files is the whole defect -- every
/// place that states it is checked here against the registrations themselves.
#[test]
fn prose_mcp_tool_counts_match_the_server() {
    let server = include_str!("../src/mcp/server.rs");
    let registered = regex::Regex::new(r#"(?m)^\s+name = "[a-z_]+","#)
        .unwrap()
        .find_iter(server)
        .count();
    assert!(
        registered >= 20,
        "only {registered} MCP tool registrations found — the pattern stopped \
         matching, so this gate is comparing prose against nothing"
    );

    let stale =
        regex::Regex::new(r"(\d+) (?:Model Context Protocol tools|MCP tools|tools \()").unwrap();
    for (path, text) in [
        ("README.md", include_str!("../README.md")),
        (
            "docs/design/mcp-write-back.md",
            include_str!("../docs/design/mcp-write-back.md"),
        ),
        ("docs/README.md", include_str!("../docs/README.md")),
    ] {
        for cap in stale.captures_iter(text) {
            let claimed: usize = cap[1].parse().unwrap();
            assert_eq!(
                claimed, registered,
                "{path} says {claimed} MCP tools; src/mcp/server.rs registers \
                 {registered}. Update the prose in the same commit as the tool."
            );
        }
    }

    // The security section states the split in WORDS, which the digit scan
    // above cannot see. It drifted to "All 32 ... Twenty-seven ... These five"
    // while the server registered 35 with 7 write verbs -- so an auditor
    // reading the write-verb table got a list that omitted `start_tls_capture`
    // and `stop_tls_capture`, the two that attach uprobes to another process.
    // A stale count in a security section is not a typo, so it is gated.
    let protocol = include_str!("../docs/mcp-protocol.md");
    let writers = regex::Regex::new(r"read_only_hint = false")
        .unwrap()
        .find_iter(include_str!("../src/mcp/server.rs"))
        .count();
    assert!(
        protocol.contains(&format!("All {registered} carry MCP annotations")),
        "docs/mcp-protocol.md does not say all {registered} tools carry annotations"
    );
    assert!(
        protocol.contains(&format!(
            "of the {registered} tools are `readOnlyHint: true`"
        )),
        "docs/mcp-protocol.md's write-verb section names a tool total other than \
         {registered}"
    );
    for tool in ["start_tls_capture", "stop_tls_capture"] {
        assert!(
            protocol.contains(&format!("| `{tool}` |")),
            "docs/mcp-protocol.md's write-verb table omits `{tool}`, which is \
             `readOnlyHint: false`. {writers} tools are write verbs and the \
             table must list every one of them."
        );
    }
}

/// No parameter doc may state a row ceiling as a fixed number.
///
/// `--mcp-max-rows` exists because, in the CLI's own words, "the right ceiling
/// belongs to the CONSUMER, not to sipnab". Five parameter docs and eight
/// table rows nonetheless said `1..=1000` or "1 to 1000", and one section
/// called the bounds "hard-coded" outright -- which is false, and tells an
/// operator who raised the cap that their setting does nothing.
///
/// The failure mode is not a stale number. It is a document that overrules a
/// setting, so the gate is on the PHRASING rather than on the value: a doc may
/// name 1000 as the DEFAULT, and may not present it as the limit.
#[test]
fn no_parameter_doc_states_a_row_ceiling_as_a_fixed_number() {
    let banned = [
        "1..=1000",
        "1 to 1000",
        "1-1000",
        "capped at 1000",
        "hard-coded to keep tool-call costs",
    ];
    let mut hits: Vec<String> = Vec::new();
    for (path, text) in [
        ("src/mcp/server.rs", include_str!("../src/mcp/server.rs")),
        ("docs/mcp-tools.md", include_str!("../docs/mcp-tools.md")),
        ("docs/mcp.md", include_str!("../docs/mcp.md")),
        (
            "website/content/docs/mcp-tools.md",
            include_str!("../website/content/docs/mcp-tools.md"),
        ),
        // The REST surface has the same shape and the same knob
        // (`--api-max-rows`), and it had the same defect: two rows said
        // "capped at 1000" where the ceiling is the operator's.
        ("docs/rest-api.md", include_str!("../docs/rest-api.md")),
        (
            "website/content/docs/api.md",
            include_str!("../website/content/docs/api.md"),
        ),
    ] {
        for phrase in banned {
            if text.contains(phrase) {
                hits.push(format!("{path}: {phrase:?}"));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "these state a row ceiling as a fixed number instead of naming \
         --mcp-max-rows, which an operator can raise: {hits:?}"
    );

    // A scan that matches nothing would pass whatever the docs said.
    let tools = include_str!("../docs/mcp-tools.md");
    assert!(
        tools.contains("--mcp-max-rows"),
        "docs/mcp-tools.md must name the knob somewhere, or this gate is \
         checking that a phrase is absent from a page it never read"
    );
}

/// The tree spells in US English, and nothing held it there.
///
/// 0.5.105 made 2,904 replacements across 274 files for exactly this reason: a
/// repository that spells one word two ways teaches a reader that neither
/// spelling is meant, and a grep for either finds half the matches. That sweep
/// shipped with NO gate, so by 0.5.122 the tree had drifted back to 166
/// British spellings across 80 files -- including test function names.
///
/// The lesson is the one bench/baseline.json learned the hard way: a one-time
/// correction with nothing holding it is a correction with a half-life. This
/// is the thing that holds it.
///
/// CHANGELOG.md is exempt and that is not laziness: 0.5.105's entry QUOTES the
/// British spellings as examples of what it replaced, so "fixing" them would
/// leave the entry saying a word was replaced by itself. LICENSES/ and
/// THIRD-PARTY-NOTICES.md are other people's text, and website/static/llms*.txt
/// is generated.
#[test]
fn the_tree_spells_in_us_english() {
    // WHOLE words, not stems. `aria-labelledby` is a standard HTML attribute
    // spelled that way by the spec and `analysis` is correct US English, so a
    // stem match flags both -- and a gate that cries wolf gets switched off.
    const BRITISH: &[&str] = &[
        "honour",
        "honours",
        "honoured",
        "honouring",
        "behaviour",
        "behaviours",
        "behavioural",
        "normalise",
        "normalised",
        "normalises",
        "normalising",
        "normalisation",
        "recognise",
        "recognised",
        "recognises",
        "recognising",
        "recognisable",
        "initialise",
        "initialised",
        "initialises",
        "initialising",
        "initialisation",
        "analyse",
        "analysed",
        "analyses",
        "analysing",
        "catalogue",
        "catalogues",
        "catalogued",
        "cataloguing",
        "colour",
        "colours",
        "coloured",
        "colouring",
        "licence",
        "licences",
        "cancelled",
        "cancelling",
        "labelled",
        "labelling",
        "modelled",
        "modelling",
        "organise",
        "organised",
        "organises",
        "organising",
        "organisation",
        "authorise",
        "authorised",
        "authorises",
        "authorising",
        "authorisation",
        "optimise",
        "optimised",
        "optimises",
        "optimising",
        "optimisation",
        "serialise",
        "serialised",
        "serialises",
        "serialising",
        "serialisation",
        "summarise",
        "summarised",
        "summarises",
        "summarising",
        "signalling",
        "signalled",
        "travelled",
        "travelling",
    ];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .args(["ls-files"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    let listing = String::from_utf8_lossy(&out.stdout);

    let patterns: Vec<regex::Regex> = BRITISH
        .iter()
        .map(|w| {
            regex::Regex::new(&format!(r"(?i)\b{w}\b"))
                .unwrap_or_else(|e| panic!("bad pattern for {w}: {e}"))
        })
        .collect();

    let mut hits: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for f in listing.split_whitespace() {
        if f.starts_with("target/")
            || f.starts_with("LICENSES/")
            || f.starts_with("website/static/")
            || f == "THIRD-PARTY-NOTICES.md"
            || f == "CHANGELOG.md"
            // This file LISTS every word it forbids, so it necessarily
            // contains all of them. Exempting it is not a loophole: the list
            // is the gate, and a gate cannot be its own violation.
            || f == "tests/docs_drift_test.rs"
            // VENDORED, and the words are the vendor's. `analyse` and
            // `organisation` are vcon.store's own spellings in their own
            // OpenAPI document, kept verbatim so the divergence tests measure
            // a real second consumer rather than an edited copy of one.
            // Named individually rather than exempting `tests/schemas/`,
            // which also holds schemas this project does author.
            || f == "tests/schemas/vcon-store-openapi.json"
            || f.ends_with(".lock")
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(root.join(f)) else {
            continue;
        };
        scanned += 1;
        for (w, re) in BRITISH.iter().zip(patterns.iter()) {
            if re.is_match(&text) {
                hits.push(format!("{f}: {w:?}"));
            }
        }
    }

    // A walk that read nothing would report a clean tree.
    assert!(
        scanned > 200,
        "only scanned {scanned} tracked files — the walk stopped early, so \
         this gate is reporting a clean tree it never looked at"
    );
    assert!(
        hits.is_empty(),
        "British spellings, {} of them. This tree is US English and 0.5.105 \
         already swept it once; without this gate it drifted back:\n  {}",
        hits.len(),
        hits.join("\n  ")
    );
}

/// The British-spelling list is not empty.
///
/// The gate above counts the files it scanned, which catches a walk that
/// stopped early -- and says nothing about a word list that emptied. With no
/// words in it the scan reads every file and reports every one of them clean,
/// which is indistinguishable from a tree that is clean. The file count and
/// the list are two different ways for the same gate to prove nothing.
#[test]
fn the_british_spelling_list_is_not_empty() {
    let src = include_str!("docs_drift_test.rs");
    let list = src
        .split("const BRITISH: &[&str] = &[")
        .nth(1)
        .expect("the spelling gate declares its list")
        .split("];")
        .next()
        .expect("the list is terminated");
    let words = list.matches('"').count() / 2;
    assert!(
        words > 20,
        "the British-spelling list holds {words} word(s), which is too few to \
         be the list this gate was written with -- and an empty one passes on \
         every file in the tree"
    );
    for must in ["behaviour", "normalise", "recognised"] {
        assert!(
            list.contains(must),
            "`{must}` is a spelling this tree has actually drifted into and \
             must stay in the list"
        );
    }
}

/// The contributing guide states the spelling rule.
///
/// Written after the gate caught `recognised` in a test file added the same
/// day. Nothing had told the writer, so the rule was met for the first time as
/// a rejected commit -- and the fix is a sentence, not a stricter gate.
#[test]
fn the_guide_states_the_us_english_rule() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let guide = std::fs::read_to_string(repo.join("CONTRIBUTING.md"))
        .expect("CONTRIBUTING.md")
        .to_ascii_lowercase();
    assert!(
        guide.contains("us english"),
        "CONTRIBUTING.md does not state that prose is US English, so a \
         contributor learns it from a failed commit"
    );
    assert!(
        guide.contains("the_tree_spells_in_us_english"),
        "and it must name the gate, so the reader can see what checks it"
    );
}

/// Every packet applier must carry SDP provenance, not just three of four.
///
/// There are four independent appliers -- single-threaded live, the `--cores`
/// shard, batch, and TUI file-open -- and a change made to some of them is the
/// defect class this codebase names most often. This is that class, caught in
/// the act: three called `link_to_dialog_with_sdp_from` and passed
/// `SdpProvenance::observed(..)`, while `app/batch.rs` called
/// `link_to_dialog_with_sdp`, which hardcodes `SdpProvenance::unknown()`.
///
/// The consequence was invisible because nothing errored. Provenance is what
/// lets a stale offer be aged out (F3) and what makes a binding that crossed
/// sources say so. With `unknown()`, `sdp_endpoint_expired` returns false for
/// every endpoint -- it refuses to guess an age it was never told -- so on the
/// `-N -I file` path, the most-used offline path there is, an offer stale
/// enough to belong to a PREVIOUS call on the same socket could still claim a
/// stream. And a comment in the TUI applier asserted parity with batch that
/// batch did not provide, which is why nobody noticed.
///
/// A source scan rather than a behavioural test on purpose: the failure is
/// "one of four call sites differs", and that is a property of the source.
#[test]
fn every_packet_applier_carries_sdp_provenance() {
    const APPLIERS: &[&str] = &[
        "src/pipeline.rs",
        "src/parallel.rs",
        "src/app/batch.rs",
        "src/tui/controllers/file_open.rs",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut carrying = 0usize;
    let mut bare: Vec<&str> = Vec::new();
    for f in APPLIERS {
        let text =
            std::fs::read_to_string(root.join(f)).unwrap_or_else(|e| panic!("read {f}: {e}"));
        // The provenance-carrying call is a strict superset of the bare one's
        // name, so count the bare form only where it is NOT the `_from` call.
        let with = text.matches("link_to_dialog_with_sdp_from(").count();
        let total = text.matches("link_to_dialog_with_sdp").count();
        if with > 0 {
            carrying += 1;
        }
        // Every mention must be the `_from` form, discounting doc references.
        let bare_calls = total
            - with
            - text.matches("link_to_dialog_with_sdp`").count()
            - text.matches("link_to_dialog_with_sdp](").count();
        if bare_calls > 0 {
            bare.push(f);
        }
    }

    assert_eq!(
        carrying,
        APPLIERS.len(),
        "only {carrying} of {} appliers link SDP with provenance — the scan \
         may also have stopped matching, so check the call name before \
         raising this",
        APPLIERS.len()
    );
    assert!(
        bare.is_empty(),
        "these appliers call `link_to_dialog_with_sdp`, which hardcodes \
         SdpProvenance::unknown() and silently disables F3 stale-offer aging \
         on that surface: {bare:?}"
    );
}

/// The documented pre-push gate count must match the hook.
///
/// Three documents carried hand-maintained copies of the hook's gate list and
/// all three were wrong, differently: `docs/internals/README.md` said four
/// where the hook has eight, `CONTRIBUTING.md` listed a WASM-bundle gate that
/// had been DELETED, and `docs/internals/testing.md` described that same dead
/// gate as live. Nothing compared the prose to `.githooks/*`, so the only way
/// to notice was to read both.
///
/// Derived from the hook's own `# -- Hard gate` markers rather than restated,
/// which is the difference between a number that stays true and a number that
/// was true once.
#[test]
fn documented_pre_push_gate_count_matches_the_hook() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hook =
        std::fs::read_to_string(root.join(".githooks/pre-push")).expect("read .githooks/pre-push");
    let gates = hook.matches("\n# -- Hard gate").count();

    // A marker that stopped matching would report zero gates and agree with
    // nothing, which is indistinguishable from a hook that lost them all.
    assert!(
        gates >= 5,
        "found only {gates} `# -- Hard gate` markers — the marker shape \
         changed, so this gate is comparing prose against nothing"
    );

    let spelled = match gates {
        4 => "four",
        5 => "five",
        6 => "six",
        7 => "seven",
        8 => "eight",
        9 => "nine",
        10 => "ten",
        // Two arms ahead of the hook, deliberately.
        // `the_gate_count_spelling_table_covers_one_more_than_today` requires
        // the NEXT count to exist, so adding a gate is a documentation edit
        // rather than a panic about a missing match arm several minutes into
        // a CI run.
        11 => "eleven",
        12 => "twelve",
        n => panic!("no spelling for {n} gates; add one rather than dropping the check"),
    };

    for (path, text) in [
        ("CONTRIBUTING.md", include_str!("../CONTRIBUTING.md")),
        (
            "docs/internals/build-ci-release.md",
            include_str!("../docs/internals/build-ci-release.md"),
        ),
        (
            "docs/internals/README.md",
            include_str!("../docs/internals/README.md"),
        ),
    ] {
        // Each of these names a count of pre-push gates somewhere. Any OTHER
        // spelled number next to "hard gate" is the drift this catches.
        for wrong in ["four", "five", "six", "seven", "eight", "nine", "ten"] {
            if wrong == spelled {
                continue;
            }
            let phrase = format!("{wrong} hard gates");
            assert!(
                !text.contains(&phrase),
                "{path} says \"{phrase}\" but .githooks/pre-push has {gates} \
                 (`# -- Hard gate` markers). Derive it or fix it — three \
                 documents already drifted here, in three different directions."
            );
        }
    }
}

/// The deleted WASM-bundle gate must not be documented as live.
///
/// It guarded a committed binary that is no longer committed. It was described
/// as an active blocking gate in three prose files and their published
/// mirrors, long after the hook block became a comment explaining its own
/// removal — which is a documentation failure with a very long tail, because
/// a contributor reads it as a rule they are breaking.
#[test]
fn the_removed_wasm_bundle_gate_is_not_documented_as_live() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hook = std::fs::read_to_string(root.join(".githooks/pre-commit"))
        .expect("read .githooks/pre-commit");
    // The hook keeps the reasoning as a comment; it must stay a comment.
    assert!(
        hook.contains("That gate is gone with the binary it guarded"),
        "the removal rationale left .githooks/pre-commit — if the gate came \
         back, delete this test and the one above it deliberately"
    );

    for (path, text) in [
        ("CONTRIBUTING.md", include_str!("../CONTRIBUTING.md")),
        (
            "docs/internals/testing.md",
            include_str!("../docs/internals/testing.md"),
        ),
    ] {
        assert!(
            !text.contains("without a rebuilt bundle")
                && !text.contains("without staging a rebuilt bundle"),
            "{path} describes the deleted WASM-bundle gate as live"
        );
    }
}

/// The pre-push wasm check and CI's must compile for the SAME target.
///
/// `cargo check --features wasm` without `--target` compiles for the HOST,
/// where every `#[cfg(not(target_arch = "wasm32"))]` is inert. It then proves
/// the `wasm` feature compiles for Linux and nothing whatever about wasm.
///
/// ci.yml found that and fixed its own copy. The hook's copy was not fixed
/// alongside it, and the two disagreed silently until a module that compiled
/// fine on the host failed the real target in CI and blocked a website deploy.
/// Two copies of one rule, which is the shape this repo has been bitten by
/// before -- the codespell path list drifted the same way.
///
/// Pinned on the flag rather than on the whole command string, so reformatting
/// either file does not fail this, but dropping the target does.
#[test]
fn the_wasm_check_targets_wasm_in_both_the_hook_and_ci() {
    const TRIPLE: &str = "wasm32-unknown-unknown";
    let hook = include_str!("../.githooks/pre-push");
    let ci = include_str!("../.github/workflows/ci.yml");

    for (label, text) in [
        (".githooks/pre-push", hook),
        (".github/workflows/ci.yml", ci),
    ] {
        // Anti-vacuity: a file that no longer runs a wasm check at all would
        // otherwise satisfy every assertion below by having nothing to check.
        let runs: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("cargo check") && l.contains("--features wasm"))
            .collect();
        assert!(
            !runs.is_empty(),
            "{label} no longer runs a wasm `cargo check` at all — either it was \
             removed (delete this gate too) or the line changed shape and this \
             gate is now checking nothing"
        );
        // `--target` and not the literal triple: the hook passes it through a
        // shell variable, so pinning the spelling would fail on a file that is
        // entirely correct. What must hold is that EVERY wasm check names a
        // target, and that the only target either file names is the wasm one.
        for run in &runs {
            assert!(
                run.contains("--target"),
                "{label} runs a wasm check with no `--target`, so it compiles \
                 for the HOST and proves nothing about wasm:\n  {run}"
            );
        }
        assert!(
            text.contains(TRIPLE),
            "{label} passes a `--target` that is never resolved to {TRIPLE}"
        );
    }
}

/// Each prose gate's path list has ONE source, and all three runners read it.
///
/// There are two lists -- vale's and codespell's -- and each had three copies:
/// `.githooks/pre-push`, `scripts/preflight.sh` and
/// `.github/workflows/quality.yml`. The codespell copies had already drifted,
/// under a comment in the hook reading "CI invokes codespell over this exact
/// path list; keep them identical". They were not identical: the hook omitted
/// `bench`, the operator harness, so a misspelling there passed the gate that
/// exists to catch it and turned main red instead. Nothing checked the property
/// that comment asserted. The vale copies still agreed, which is not the same
/// as being kept in agreement.
///
/// That is the shape `.config/code-trees.txt` already exists to end, and its
/// header records what the same drift cost when that list was typed out five
/// times. This is the same fix for the other two lists.
///
/// The two lists are deliberately two FILES rather than one: vale does not lint
/// `.rs`, so codespell covers `src` and `examples` and vale must not. Merging
/// them would either silence codespell on Rust prose or hand vale trees it
/// cannot read.
#[test]
fn the_prose_gate_path_lists_have_one_source() {
    /// The runners that must READ a list rather than restate it.
    ///
    /// `.githooks/pre-commit` joined them when the prose gates moved to where
    /// they are cheap to fix; it reaches the lists through the shared script,
    /// as the other two hooks now do.
    const RUNNERS: [&str; 4] = [
        ".githooks/pre-commit",
        ".githooks/pre-push",
        "scripts/preflight.sh",
        ".github/workflows/quality.yml",
    ];
    /// The one place the three hooks resolve their tools and read the lists.
    const SHARED_SCRIPT: &str = "scripts/prose-gates.sh";
    /// (list file, the tool's own name, fewest entries a non-gutted list has).
    ///
    /// The tool name scopes the search below. A runner also invokes lychee and
    /// several cargo gates, and those carry path lists of their own that
    /// legitimately overlap this one -- lychee's
    /// `'docs/**/*.md' 'README.md' 'CONTRIBUTING.md' 'SECURITY.md'` shares three
    /// entries with codespell's list and is not a copy of it. Scanning the whole
    /// file rejected that line, so the search is confined to each tool's region.
    const LISTS: [(&str, &str, usize); 2] = [
        (".config/codespell-paths.txt", "codespell", 10),
        (".config/vale-paths.txt", "vale", 4),
    ];
    /// How far from a mention of the tool a line still counts as its region.
    const WINDOW: usize = 8;

    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    for (list_file, tool, floor) in LISTS {
        let raw = std::fs::read_to_string(repo.join(list_file)).unwrap_or_else(|e| {
            panic!(
                "{list_file} is missing ({e}). It is the single source for the \
                 paths {tool} runs over; all three runners read it."
            )
        });
        let paths: Vec<String> = raw
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();

        // Anti-vacuity. A gutted list satisfies everything below by naming
        // nothing, and both tools exit 0 over no paths -- a gate reporting
        // safety it is not providing.
        assert!(
            paths.len() >= floor,
            "{list_file} yielded only {} path(s) ({paths:?}), fewer than {floor} \
             -- the list or this parser is broken, and every {tool} run built on \
             it just went blind",
            paths.len()
        );

        // The shared script is where "one source" actually lives now, so it
        // has to read the file rather than merely be sourced. Without this the
        // gate would pass on three hooks sourcing a script that reads nothing.
        let shared = std::fs::read_to_string(repo.join(SHARED_SCRIPT))
            .unwrap_or_else(|e| panic!("cannot read {SHARED_SCRIPT}: {e}"));
        assert!(
            shared
                .lines()
                .any(|l| l.contains(list_file) && !l.trim_start().starts_with('#')),
            "{SHARED_SCRIPT} does not read {list_file}. It is what the hooks \
             source instead of reading the list themselves, so if it stops \
             reading the file nothing does."
        );

        // A path that is not there is a path the tool silently skips.
        for p in &paths {
            assert!(
                repo.join(p).exists(),
                "{list_file} names {p}, which is not in the repository"
            );
        }

        for runner in RUNNERS {
            let text = std::fs::read_to_string(repo.join(runner))
                .unwrap_or_else(|e| panic!("cannot read {runner}: {e}"));

            // On a line that RUNS, not merely one that mentions it. A comment
            // naming the file satisfied this while the code beside it carried a
            // hardcoded list -- found by mutation, not by reading.
            //
            // Reading it directly OR sourcing the script that does. The three
            // hooks stopped reading these files themselves when the tool
            // resolution moved into scripts/prose-gates.sh, and this assertion
            // failed all three -- correctly, against a definition of "reader"
            // that predated the shared script. What must stay true is that ONE
            // place reads the list; where that place sits is an implementation
            // detail this gate should not pin.
            let reads_directly = text
                .lines()
                .any(|l| l.contains(list_file) && !l.trim_start().starts_with('#'));
            let sources_shared = text
                .lines()
                .any(|l| l.contains(SHARED_SCRIPT) && !l.trim_start().starts_with('#'));
            assert!(
                reads_directly || sources_shared,
                "{runner} neither reads {list_file} nor sources {SHARED_SCRIPT}. \
                 The list has one source; a runner that only NAMES it and keeps \
                 its own copy is a second one."
            );

            let lines: Vec<&str> = text.lines().collect();
            let near: std::collections::BTreeSet<usize> = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.to_lowercase().contains(tool))
                .flat_map(|(i, _)| i.saturating_sub(WINDOW)..=(i + WINDOW).min(lines.len() - 1))
                .collect();

            // If the gate were renamed or removed, every assertion below would
            // pass by examining nothing.
            assert!(
                !near.is_empty(),
                "{runner} no longer mentions {tool} at all -- either the gate was \
                 removed (drop it from LISTS here too) or it was renamed, and \
                 this check now examines nothing"
            );

            for n in near {
                let line = lines[n];
                // Comments are exempt, and only comments. A comment cannot hand
                // a stale list to a tool, and refusing prose that names three
                // trees would make this unsatisfiable for any file that explains
                // itself -- which every file here does, at length.
                if line.trim_start().starts_with('#') || line.contains(list_file) {
                    continue;
                }
                // Whole tokens, not substrings: `bench` occurs inside
                // `benchmarks.md`, so a line naming the two benchmark pages
                // scored three "entries" while restating nothing.
                // Quotes and `=` separate tokens as surely as a space does:
                // `CODESPELL_PATHS="src tests docs"` is three paths, and
                // splitting on whitespace alone saw `CODESPELL_PATHS="src` as
                // one unmatched token and scored it 2. Mutation caught that;
                // reading it did not.
                let normalised: String = line
                    .chars()
                    .map(|c| match c {
                        '"' | '\'' | '=' | '\\' | ',' | ';' | '(' | ')' => ' ',
                        other => other,
                    })
                    .collect();
                let hits = normalised
                    .split_whitespace()
                    .filter(|tok| paths.iter().any(|p| p == tok))
                    .count();
                assert!(
                    hits < 3,
                    "{runner}:{} restates {list_file} ({hits} of its entries on \
                     one line, inside the {tool} gate). Read the file instead:\n  {}",
                    n + 1,
                    line.trim()
                );
            }
        }
    }
}

/// The vale version pin has ONE source, and the runners derive it.
///
/// The version is part of the check rather than a detail: Vale.Spelling
/// consults a vocabulary that resolves differently across binaries, so a run on
/// the wrong version is evidence about a different tool. `.githooks/pre-push`
/// says exactly that, and then carried `VALE_PIN='3.16.0'` as its own literal
/// while `scripts/preflight.sh` derived the same number from
/// `.github/workflows/quality.yml`. One of the three read the source and two
/// did not agree by construction.
///
/// A bump in CI would have left the hook comparing against a stale pin and
/// reporting NOT CHECKED for a correct binary -- a gate that turns itself off
/// and says so quietly, which is the shape the corpus and wasm gates were both
/// found in this week.
#[test]
fn the_vale_version_pin_has_one_source() {
    const CI: &str = ".github/workflows/quality.yml";
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let ci = std::fs::read_to_string(repo.join(CI)).expect("read quality.yml");
    let pin = ci
        .lines()
        .find_map(|l| l.trim().strip_prefix("VALE_VERSION:"))
        .map(|v| v.trim().trim_matches('\'').to_string())
        .expect("quality.yml declares no VALE_VERSION — this gate now checks nothing");
    assert!(
        pin.split('.').all(|p| p.parse::<u32>().is_ok()),
        "{CI} VALE_VERSION is {pin:?}, which is not a version"
    );

    // The pin is derived in scripts/prose-gates.sh, which the hooks source.
    // It must genuinely read the workflow, or nothing does.
    const SHARED_SCRIPT: &str = "scripts/prose-gates.sh";
    let shared = std::fs::read_to_string(repo.join(SHARED_SCRIPT))
        .unwrap_or_else(|e| panic!("cannot read {SHARED_SCRIPT}: {e}"));
    // On a line that reads it. Mutation broke the derivation and this still
    // passed, because the path also appears in the comment explaining it --
    // `contains` proves the string is present, never that it is used.
    assert!(
        shared
            .lines()
            .any(|l| { l.contains(CI) && !l.trim_start().starts_with('#') && l.contains("grep") }),
        "{SHARED_SCRIPT} does not GREP {CI} for the vale version, and it is \
         where every hook now gets it. Naming the file in a comment is not \
         reading it."
    );

    for runner in [
        ".githooks/pre-commit",
        ".githooks/pre-push",
        "scripts/preflight.sh",
    ] {
        let text = std::fs::read_to_string(repo.join(runner))
            .unwrap_or_else(|e| panic!("cannot read {runner}: {e}"));

        // Derived here, or derived by the script this sources. Either way the
        // literal must not appear: that is what "one source" means.
        assert!(
            text.contains(CI) || text.contains(SHARED_SCRIPT),
            "{runner} neither reads {CI} for the vale version nor sources \
             {SHARED_SCRIPT}. The pin has one source; a runner carrying its own \
             is a second one."
        );

        for (n, line) in text.lines().enumerate() {
            if line.trim_start().starts_with('#') || line.contains(CI) {
                continue;
            }
            assert!(
                !line.contains(&pin),
                "{runner}:{} hardcodes the vale version {pin}. Derive it from \
                 {CI} instead, as the other runner does:\n  {}",
                n + 1,
                line.trim()
            );
        }
    }
}

/// No ratchet writes its expected value twice.
///
/// A ratchet carries a maintained count raised by hand as the repository grows,
/// and the idiom writes the number once as the assertion's expected value and
/// again in its own failure message. Raising one and not the other is a single
/// keystroke, produces no error, and leaves the gate telling whoever it fails
/// next to expect a number nobody expects.
///
/// Found three times in one day: the table-count ratchet, the packaging-path
/// ratchet, and `no_documentation_table_repeats_a_row`, where the value had
/// already been raised 159 -> 163 with the message still reading 159. It is the
/// defect the ratchets exist to catch -- a documented value drifting from what
/// produces it -- occurring inside the gates themselves, which is why finding it
/// by eye had not worked.
///
/// The checker is `scripts/check-ratchet-messages.py`, and it is the only
/// implementation: a Rust reimplementation would be a second rule that agrees
/// today and drifts tomorrow, which is the shape this whole area has spent the
/// week removing.
#[test]
fn no_ratchet_repeats_its_own_expected_value() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = repo.join("scripts/check-ratchet-messages.py");
    assert!(script.exists(), "missing {}", script.display());

    let out = std::process::Command::new("python3")
        .arg(&script)
        .current_dir(repo)
        .output()
        .expect("run scripts/check-ratchet-messages.py (python3 must be on PATH)");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a ratchet names its expected value in its own message.\n\
         Reproduce: python3 scripts/check-ratchet-messages.py\n\n{stdout}\n{stderr}"
    );

    // The checker reports what it read. A parser that stopped matching would
    // print a clean tree having examined nothing, which is the failure this
    // assertion -- and the checker's own floor -- exist to refuse.
    let scanned: u32 = stdout
        .split_whitespace()
        .skip_while(|w| *w != "checked")
        .nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(
        scanned > 500,
        "the checker reported {scanned} assertions scanned, which is too few to \
         be the real tree -- it passed by reading almost nothing:\n{stdout}"
    );
}

/// The prose gates resolve their tools in ONE place, and all three hooks use it.
///
/// `vale` and `codespell` are each resolved the same way in more than one
/// runner: an env-var escape hatch (`VALE_BIN`, `CODESPELL_BIN`), a PATH
/// lookup, a version pin read from the workflow, and a skip-with-a-stated-
/// reason path that keeps a missing tool from reading as a pass. That is four
/// decisions, and every copy of them is a chance for one runner to be laxer
/// than another -- which is exactly what the path lists did before
/// `.config/vale-paths.txt` and `.config/codespell-paths.txt`.
///
/// It also blocked the fix for the gates' real problem. They ran only at
/// pre-push, so work that satisfied pre-commit met them at the push with the
/// commit already made, costing a full gate cycle each time. Adding them to
/// pre-commit by pasting the logic a third time would have bought that at the
/// price of the duplication above; `scripts/prose-gates.sh` is what makes the
/// third caller free.
#[test]
fn the_prose_gate_logic_has_one_source() {
    const SHARED: &str = "scripts/prose-gates.sh";
    /// Every runner that must SOURCE the shared script rather than reimplement it.
    const RUNNERS: [&str; 3] = [
        ".githooks/pre-commit",
        ".githooks/pre-push",
        "scripts/preflight.sh",
    ];
    /// Decisions that belong to the shared script alone.
    ///
    /// Resolution SYNTAX, not the env-var names. Every runner still tells a
    /// reader "point VALE_BIN at one" when the gate cannot run, and that advice
    /// is rendering, not resolution -- matching on the bare name rejected the
    /// printf that gives it.
    const TOOL_RESOLUTION: [&str; 4] = [
        "${VALE_BIN:-}",
        "${CODESPELL_BIN:-}",
        "command -v vale",
        "VALE_VERSION:",
    ];

    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let shared = std::fs::read_to_string(repo.join(SHARED)).unwrap_or_else(|e| {
        panic!("{SHARED} is missing ({e}); it is where the prose gates resolve their tools")
    });

    // Anti-vacuity: an empty stub would satisfy every assertion below.
    for needle in TOOL_RESOLUTION {
        assert!(
            shared.contains(needle),
            "{SHARED} does not mention {needle} -- the resolution it is supposed \
             to own has been moved back out, or this list is stale"
        );
    }

    for runner in RUNNERS {
        let text = std::fs::read_to_string(repo.join(runner))
            .unwrap_or_else(|e| panic!("cannot read {runner}: {e}"));

        // SOURCED, not mentioned. Mutation replaced the `.` line with a
        // hardcoded list and this passed, because the comment above it still
        // named the script.
        //
        // Two conditions rather than one literal `. path` line: scripts/
        // preflight.sh assigns the path to a variable first, so it can fall
        // back to a relative path when `git rev-parse` finds no repository,
        // and then sources the VARIABLE. Pinning the spelling of the source
        // line failed that file while it was entirely correct -- the same trap
        // the wasm gate hit, and the reason it pins `--target` and the triple
        // instead of a command string.
        let names_it = text
            .lines()
            .any(|l| !l.trim_start().starts_with('#') && l.contains(SHARED));
        let sources_something = text
            .lines()
            .any(|l| l.trim_start().starts_with(". ") && !l.trim_start().starts_with('#'));
        assert!(
            names_it && sources_something,
            "{runner} does not source {SHARED} in code (names it: {names_it}, \
             has a source line: {sources_something}). Naming it in a comment is \
             not using it. The prose gates run in all three hooks and resolve \
             their tools in one place."
        );

        for needle in TOOL_RESOLUTION {
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with('#') || line.contains(SHARED) {
                    continue;
                }
                assert!(
                    !line.contains(needle),
                    "{runner}:{} resolves the tool itself ({needle}). That \
                     decision belongs to {SHARED}:\n  {}",
                    n + 1,
                    line.trim()
                );
            }
        }
    }
}

/// `llms.txt` and `llms-full.txt` are current with the pages they aggregate.
///
/// These two files had no gate at all. `site_internals_mirror_is_current`
/// compares `website/content/docs/internals` against `docs/internals` and stops
/// there, so the aggregate could drift from its own sources with every check
/// green — and did, through a full local hook and a green CI run.
///
/// The trap is which generator owns them. `build-site-pages.py` writes them
/// from ALL the published pages, `docs/internals/` included;
/// `build-site-internals.py` does not touch them. So editing an internals page
/// and running only the internals generator refreshes the mirror a gate DOES
/// check and leaves these two behind.
#[test]
fn llms_aggregates_are_current() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // pid and line, never a fixed path: two tests sharing one would race, and a
    // leftover from a killed run would be read as this run's output.
    let tmp = std::env::temp_dir().join(format!("sipnab-llms-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&tmp);

    // argv[2] keeps the generator off the committed files. Without it this
    // gate would OVERWRITE the very thing it is checking and always pass.
    let out = std::process::Command::new("python3")
        .arg(repo.join("scripts/build-site-pages.py"))
        .arg(tmp.join("pages"))
        .arg(tmp.join("static"))
        .current_dir(repo)
        .output()
        .expect("run scripts/build-site-pages.py — python3 must be on PATH");
    assert!(
        out.status.success(),
        "build-site-pages.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut stale = Vec::new();
    for name in ["llms.txt", "llms-full.txt"] {
        let fresh = std::fs::read_to_string(tmp.join("static").join(name))
            .unwrap_or_else(|e| panic!("the generator wrote no {name}: {e}"));
        let have =
            std::fs::read_to_string(repo.join("website/static").join(name)).unwrap_or_default();
        assert!(
            !fresh.is_empty(),
            "{name} generated EMPTY — an empty file would match an empty \
             committed one and this gate would pass on nothing"
        );
        if fresh != have {
            stale.push(name);
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        stale.is_empty(),
        "website/static is stale — regenerate with \
         `python3 scripts/build-site-pages.py` and commit: {stale:?}"
    );
}

/// Every function in the vCon modules carries its OWN doc comment.
///
/// Inserting a function immediately before an existing one splits that one's
/// doc block: the new function inherits documentation describing something
/// else, and the original is left with none. It happened four times in one
/// day's work on this module -- `Dialog::empty` took `Dialog::bare`'s docs,
/// `media_budget` took the first half of `export_vcon_selection`'s and left it
/// a dangling fragment, and twice more besides.
///
/// Clippy catches only the PUBLIC half of that, through `missing_docs`. A
/// private function that loses its documentation to a new neighbour is
/// invisible to it, and the new function looks documented because it is
/// wearing somebody else's comment.
///
/// The check is deliberately shallow: it asks whether a `fn` has any doc line
/// above it, not whether the words are right. A shallow check that fires on
/// the actual failure mode beats a clever one that cannot run.
#[test]
fn every_function_in_the_vcon_modules_has_its_own_doc_comment() {
    // Modules where the vCon work concentrated, and where the splitting
    // actually happened. Not the whole tree: a gate that reports two hundred
    // pre-existing gaps is a gate somebody switches off.
    const MODULES: &[&str] = &["src/output/vcon.rs", "src/app/batch.rs"];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut undocumented: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for module in MODULES {
        let text = std::fs::read_to_string(root.join(module))
            .unwrap_or_else(|e| panic!("read {module}: {e}"));
        let lines: Vec<&str> = text.lines().collect();
        let mut in_tests = false;

        for (n, line) in lines.iter().enumerate() {
            // The test module's helpers are exempt: they are read beside their
            // single call site, and requiring docs there would be noise.
            if line.trim_start().starts_with("mod tests") {
                in_tests = true;
            }
            if in_tests {
                continue;
            }
            let t = line.trim_start();
            let is_fn = (t.starts_with("fn ")
                || t.starts_with("pub fn ")
                || t.starts_with("pub(crate) fn ")
                || t.starts_with("async fn "))
                && line.starts_with(['f', 'p', 'a']);
            if !is_fn {
                continue;
            }
            checked += 1;

            // Walk upward past attributes to whatever documents this item.
            let mut i = n;
            let mut documented = false;
            while i > 0 {
                i -= 1;
                let above = lines[i].trim_start();
                if above.starts_with("#[") || above.starts_with("#!") {
                    continue;
                }
                documented = above.starts_with("///") || above.starts_with("//!");
                break;
            }
            if !documented {
                let name = t.split('(').next().unwrap_or(t);
                undocumented.push(format!("{module}:{}: {name}", n + 1));
            }
        }
    }

    assert!(
        checked > 40,
        "the fn scan matched only {checked} functions, so it is checking far \
         less than these modules contain and would pass on an empty file"
    );
    assert!(
        undocumented.is_empty(),
        "these functions carry no doc comment of their own. The usual cause is \
         an insertion between an existing doc block and the item it described, \
         which leaves the newcomer wearing those docs and the original with \
         none:\n  {}",
        undocumented.join("\n  ")
    );
}

/// A doc comment block is never separated from its item by a blank line.
///
/// The other half of the same defect. Removing a function that sat between a
/// doc block and its neighbour leaves the block orphaned -- attached to
/// nothing, describing something deleted. That happened when
/// `apply_deny_filter` came out: its documentation stayed behind, explaining
/// why `streams` is filtered alongside `dialogs`, with no function under it.
///
/// Clippy sees an orphaned block only as `empty_line_after_doc_comments`, and
/// only sometimes. This is the shape stated directly.
#[test]
fn no_doc_comment_block_is_orphaned_from_its_item() {
    const MODULES: &[&str] = &["src/output/vcon.rs", "src/app/batch.rs"];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut orphaned: Vec<String> = Vec::new();
    let mut blocks = 0usize;

    for module in MODULES {
        let text = std::fs::read_to_string(root.join(module))
            .unwrap_or_else(|e| panic!("read {module}: {e}"));
        let lines: Vec<&str> = text.lines().collect();

        for (n, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("///") {
                continue;
            }
            // Only the LAST line of a block matters: what follows it is what
            // the block documents.
            let next = lines.get(n + 1).map(|l| l.trim()).unwrap_or("");
            if next.starts_with("///") {
                continue;
            }
            blocks += 1;
            if next.is_empty() {
                orphaned.push(format!("{module}:{}", n + 1));
            }
        }
    }

    assert!(
        blocks > 40,
        "matched only {blocks} doc blocks, so this gate is reading almost \
         nothing and would pass on a file with no comments at all"
    );
    assert!(
        orphaned.is_empty(),
        "a doc comment block is followed by a blank line, so it documents \
         nothing. The usual cause is removing the function that sat beneath \
         it:\n  {}",
        orphaned.join("\n  ")
    );
}

/// Every ratchet constant records why it moved, naming the value it moved to.
///
/// Four ratchets moved in one day's work -- markdown files 170 -> 172 -> 175,
/// tables 672 -> 692, the docs-page walk 49 -> 50, wiki links 501 -> 502. Each
/// one is a number somebody will raise again, and a raise with no attribution
/// is indistinguishable from a raise that papered over a real regression: the
/// gate's own message says "FEWER means the sweep stopped reading part of the
/// tree", and the only thing separating a legitimate bump from hiding that is
/// a sentence saying which files account for the difference.
///
/// The existing constants all carry that sentence. This makes it a rule rather
/// than a habit.
#[test]
fn every_ratchet_constant_records_the_value_it_moved_to() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let re = regex::Regex::new(r"(?m)^\s*const (EXPECTED_[A-Z_]+): usize = (\d+);").unwrap();

    let mut checked = 0usize;
    let mut unattributed: Vec<String> = Vec::new();

    for file in ["tests/docs_drift_test.rs", "tests/link_integrity_test.rs"] {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let lines: Vec<&str> = text.lines().collect();

        for (n, line) in lines.iter().enumerate() {
            let Some(cap) = re.captures(line) else {
                continue;
            };
            let (name, value) = (&cap[1], &cap[2]);
            checked += 1;

            // The comment block immediately above must mention the new value.
            // Walking up rather than looking at one line: these constants
            // carry several releases of history, newest last.
            let mut mentions = false;
            let mut i = n;
            while i > 0 {
                i -= 1;
                let above = lines[i].trim_start();
                if !above.starts_with("//") {
                    break;
                }
                if above.contains(value) {
                    mentions = true;
                    break;
                }
            }
            if !mentions {
                unattributed.push(format!("{file}:{}: {name} = {value}", n + 1));
            }
        }
    }

    assert!(
        checked >= 4,
        "matched only {checked} ratchet constants; the naming convention \
         changed and this gate is reading almost nothing"
    );
    assert!(
        unattributed.is_empty(),
        "these ratchets moved without a comment naming the value they moved \
         to. Attribute the delta per file before raising one -- a number that \
         moved for reasons nobody wrote down cannot be told apart from one \
         that hid a regression:\n  {}",
        unattributed.join("\n  ")
    );
}

/// No gate in this tree treats an empty scan as a pass.
///
/// The defect class behind more of one day's mistakes than any single bug: a
/// check whose FAILURE and whose INABILITY TO RUN look identical. A spelling
/// probe placed in an untracked file, which the gate reads from `git ls-files`
/// and therefore never saw. A mutation that did not compile, so the test binary
/// never built and the survivor looked like a passing test. A site monitor
/// grepping for `href="/notes/"` against HTML that escapes every slash, which
/// reported zero notes whatever was published.
///
/// Every scanning gate here already answers it the same way: count what you
/// looked at, and refuse to pass on zero. This asserts the convention holds, so
/// the next scanning gate cannot quietly skip it.
#[test]
fn every_scanning_gate_refuses_to_pass_on_an_empty_scan() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Gates that walk a corpus: each must assert a floor on what it examined.
    const SCANNERS: &[(&str, &str)] = &[
        ("tests/docs_drift_test.rs", "checked"),
        ("tests/docs_drift_test.rs", "scanned"),
        ("tests/docs_drift_test.rs", "blocks"),
        ("tests/link_integrity_test.rs", "checked"),
    ];

    let mut proven = 0usize;
    for (file, counter) in SCANNERS {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        // A counter is only meaningful if something bounds it below. Two
        // spellings qualify, and the second is the stronger one: an exact
        // `assert_eq!(counter, EXPECTED_N)` pins the corpus size rather than
        // merely refusing zero. The first draft of this gate recognized only
        // the floor form and reported a gate using the stricter one as
        // unguarded -- a check that is wrong about what counts as a check.
        let floor = regex::Regex::new(&format!(r"assert!\(\s*{counter}\s*>=?\s*\d+")).unwrap();
        let exact = regex::Regex::new(&format!(r"assert_eq!\(\s*\n?\s*{counter},")).unwrap();
        if floor.is_match(&text) || exact.is_match(&text) {
            proven += 1;
        }
    }

    assert_eq!(
        proven,
        SCANNERS.len(),
        "a scanning gate counts what it examined but never asserts a floor on \
         that count, so an empty corpus reads as a clean pass. Every entry in \
         SCANNERS must have an `assert!(<counter> > N, ...)` beside its loop."
    );
}

/// Every refusal in `pre-push` sits inside a marked gate.
///
/// `documented_pre_push_gate_count_matches_the_hook` counts `# -- Hard gate`
/// markers and compares that number against three documents. It cannot see a
/// step that has no marker: one added without it leaves the count low, the
/// prose right, and the new gate invisible to the check meant to keep them in
/// step. The site build shipped exactly that way -- ten gates, a count of
/// nine, and three documents I had just corrected to "ten" turning CI red.
///
/// The invariant is containment, not a one-to-one count. A single gate refuses
/// for several distinct reasons: the feature-combo gate blocks for a bad combo
/// AND for a broken wasm build, and the tag gate blocks for a red run AND for
/// no runs at all. Counting `Push blocked` lines and expecting one per marker
/// was this test's first draft, and it reported the hook as broken when the
/// hook was right.
#[test]
fn every_refusal_in_pre_push_sits_inside_a_marked_gate() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hook =
        std::fs::read_to_string(root.join(".githooks/pre-push")).expect("read .githooks/pre-push");

    let first_marker = hook
        .find("\n# -- Hard gate")
        .expect("pre-push has no `# -- Hard gate` markers at all");

    let markers = hook.matches("\n# -- Hard gate").count();
    let refusals = hook.matches("Push blocked").count();
    assert!(
        markers >= 5 && refusals >= markers,
        "found {markers} markers and {refusals} refusals -- one of these \
         shapes changed, and this gate is comparing nothing to nothing"
    );

    // Anything that can block before the first marker is a gate the count
    // cannot see.
    let orphans = hook[..first_marker].matches("Push blocked").count();
    assert_eq!(
        orphans, 0,
        "pre-push refuses a push {orphans} time(s) before its first \
         `# -- Hard gate` marker, so those gates are invisible to the count \
         the documents are checked against"
    );
}

/// The spelling table covers every count the hook can currently reach.
///
/// `documented_pre_push_gate_count_matches_the_hook` panics with "no spelling
/// for N gates" rather than failing quietly, which is right — but it means
/// adding an eleventh gate turns a documentation check into a panic about a
/// missing match arm, several minutes into a CI run. Cheaper to say so here.
#[test]
fn the_gate_count_spelling_table_covers_one_more_than_today() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hook =
        std::fs::read_to_string(root.join(".githooks/pre-push")).expect("read .githooks/pre-push");
    let gates = hook.matches("\n# -- Hard gate").count();

    let test_src =
        std::fs::read_to_string(root.join("tests/docs_drift_test.rs")).expect("read this file");
    // The arm for the NEXT gate must already exist, so adding one is a doc
    // edit rather than a panic.
    let next = gates + 1;
    let spellings = [
        (4, "four"),
        (5, "five"),
        (6, "six"),
        (7, "seven"),
        (8, "eight"),
        (9, "nine"),
        (10, "ten"),
        (11, "eleven"),
        (12, "twelve"),
    ];
    let want = spellings
        .iter()
        .find(|(n, _)| *n == next)
        .map(|(_, s)| *s)
        .unwrap_or_else(|| panic!("extend this table past {next}"));

    assert!(
        test_src.contains(&format!("=> \"{want}\"")),
        "pre-push has {gates} hard gates, so the next one makes {next}, and \
         the spelling table in \
         `documented_pre_push_gate_count_matches_the_hook` has no arm for \
         {next} (\"{want}\"). Adding a gate would panic there instead of \
         reporting a documentation mismatch."
    );
}

/// Every `FOREIGN_FLAGS` entry still describes a document that carries it.
///
/// The list exempts a flag name from `readme_long_flags_exist_in_cli`, scoped
/// to the pages that legitimately show another tool's command line -- cargo's
/// `--release`, curl's `--data-binary`, rtpengine's `--listen-ng`. Every entry
/// is a hole in that gate, deliberately cut.
///
/// A hole outlives the text that justified it. Reword the paragraph, move the
/// example to another page, drop the command entirely, and the exemption stays
/// -- so a real sipnab flag with the same name could later be documented,
/// never implemented, and pass. Entries are cheap to add under deadline; this
/// is what makes them cost something to keep.
#[test]
fn no_foreign_flag_exemption_outlives_the_text_it_was_cut_for() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut stale: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (flag, scopes) in FOREIGN_FLAGS {
        for scope in *scopes {
            checked += 1;
            let path = root.join(scope);
            let Ok(text) = std::fs::read_to_string(&path) else {
                stale.push(format!("{scope}: file does not exist (exempts --{flag})"));
                continue;
            };
            if !text.contains(&format!("--{flag}")) {
                stale.push(format!("{scope}: no longer mentions --{flag}"));
            }
        }
    }

    assert!(
        checked >= 20,
        "walked only {checked} FOREIGN_FLAGS scopes -- the list shrank or its \
         shape changed, and this gate is checking almost nothing"
    );
    assert!(
        stale.is_empty(),
        "these FOREIGN_FLAGS exemptions no longer cover any text, so they are \
         holes in `readme_long_flags_exist_in_cli` protecting nothing:\n  {}",
        stale.join("\n  ")
    );
}

/// A foreign-flag exemption never names a flag sipnab actually has.
///
/// The opposite rot, and the more dangerous one. If sipnab later grows a flag
/// whose name is already exempted for some page -- `--force`, `--output-dir`,
/// `--interface` are all plausible -- then that page can document it wrongly
/// and the gate stays silent, because the name is on the exemption list.
#[test]
fn no_foreign_flag_exemption_shadows_a_real_sipnab_flag() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let cli = std::fs::read_to_string(root.join("src/cli.rs")).expect("read src/cli.rs");

    let mut shadowed: Vec<&str> = Vec::new();
    for (flag, _) in FOREIGN_FLAGS {
        if cli.contains(&format!("long = \"{flag}\"")) {
            shadowed.push(flag);
        }
    }

    assert!(
        !FOREIGN_FLAGS.is_empty(),
        "FOREIGN_FLAGS is empty -- this gate is asserting nothing"
    );
    assert!(
        shadowed.is_empty(),
        "these names are exempted as another tool's flags AND exist in \
         src/cli.rs as sipnab's own: {shadowed:?}. While the exemption stands, \
         a page can document sipnab's version of the flag incorrectly and \
         `readme_long_flags_exist_in_cli` will not notice."
    );
}

/// Every `NOT CHECKED` in `pre-push` tells the operator what to do about it.
///
/// The hook reports a missing tool as `NOT CHECKED` rather than passing, which
/// is the right half of the rule: a gate that goes quiet when its tool is
/// absent claims a safety it is not providing. The other half is that the
/// operator now has a yellow line and a decision to make, and no basis for
/// making it — is this covered elsewhere, or did I just push unchecked?
///
/// Vale and codespell answer it ("CI runs it and it blocks", plus the install
/// line). The wasm target answers it. The feature-matrix and non-Linux
/// branches did NOT: they said a script was missing and stopped, so the one
/// message that admits a gap gave no way to close it.
///
/// Checked structurally rather than by wording, because the useful sentence
/// varies: sometimes it is an install command, sometimes it is which CI job
/// still covers you.
#[test]
fn every_not_checked_branch_in_pre_push_says_what_to_do() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hook =
        std::fs::read_to_string(root.join(".githooks/pre-push")).expect("read .githooks/pre-push");
    let lines: Vec<&str> = hook.lines().collect();

    let mut silent: Vec<String> = Vec::new();
    let mut announcements = 0usize;

    for (n, line) in lines.iter().enumerate() {
        // The ANNOUNCEMENT, not the comments explaining the convention: only a
        // printf actually reaches an operator.
        if !(line.contains("NOT CHECKED") && line.contains("printf")) {
            continue;
        }
        announcements += 1;

        // The remedy must sit INSIDE the same branch. Scanning a fixed window
        // instead let the `else` arm's own progress line count as the remedy —
        // it happens to contain "CI" — so deleting the real remedy left this
        // test passing. Stop at the branch boundary.
        let follows_up = lines
            .iter()
            .skip(n + 1)
            .take_while(|l| {
                let t = l.trim();
                !(t == "else" || t == "fi" || t.starts_with("elif"))
            })
            .any(|l| l.contains("printf") && l.contains("'    "));
        if !follows_up {
            silent.push(format!("{}: {}", n + 1, line.trim()));
        }
    }

    assert!(
        announcements >= 5,
        "found only {announcements} `NOT CHECKED` announcements — the wording \
         changed and this gate is reading nothing"
    );
    assert!(
        silent.is_empty(),
        "these `NOT CHECKED` branches leave the operator with a warning and no \
         next step. Say which CI job still covers it, or how to install the \
         tool:\n  {}",
        silent.join("\n  ")
    );
}
