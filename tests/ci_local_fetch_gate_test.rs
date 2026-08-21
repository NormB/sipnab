// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every system package a hosted CI job needs must come from a local cache
//! first, not from the Ubuntu archives on every run.
//!
//! Measured, not theorised. On 2026-08-20 the `Security audit` job of the
//! 0.5.118 CI run sat in `apt-get install -y libpcap-dev` for **15 minutes**
//! (`23:44:35Z` to `23:59:51Z`) and was cancelled, which failed the aggregate
//! `CI success` job and blocked the release tag. Nothing was wrong with the
//! code: `azure.archive.ubuntu.com` simply did not answer. The same run lost
//! `Docker` to a second external fetch — Trivy's vulnerability DB download
//! from `mirror.gcr.io` — for a combined cost of two full re-run cycles.
//!
//! The guard that was supposed to prevent this exists and cannot fire. Every
//! apt step is written `dpkg -s <pkg> || need="$need <pkg>"`, which skips the
//! install when the package is already present. That was written when these
//! jobs ran on the self-hosted box, where `libpcap-dev` is installed once and
//! stays. On a GitHub-hosted runner the package is never present, so the guard
//! evaluates to "install everything" on every job of every run — seventeen
//! sites across five workflows, each one an unbounded network fetch.
//!
//! So the rule is not "guard the install". It is: **a hosted job must not
//! reach the archives on the common path at all.** The shared composite action
//! restores the `.deb` files from `actions/cache` and installs them with
//! `dpkg -i`, which touches no network; the archives are consulted only to
//! populate a cold cache, and even then under a bounded timeout so a stall
//! costs minutes rather than a cancelled run.
//!
//! `release.yml` was deliberately NOT in scope when this file was written, and
//! that was not an oversight: its builds run inside pinned `bookworm` and
//! `cross` containers as root, where the package set is multiarch and
//! `actions/cache` has no meaning. **That half is still true and there is
//! still no `system-deps` in `release.yml`.**
//!
//! What the exclusion did not account for is that a RELEASE fetch failing is
//! strictly worse than a CI fetch failing, because a tag is already public by
//! the time it happens. Measured on 2026-08-21: the 0.5.120 release build died
//! on the netmap headers behind a bare `wget ... || exit 1` in the musl cross
//! image, `Create Release` and the Homebrew bump are `needs: build`, and so a
//! v0.5.120 tag existed with NOTHING behind it until the job was re-run by
//! hand. So the release path is now in scope for the properties that do not
//! need a cache — bound it, retry it, checksum it, and make the log name the
//! command that actually failed — under "The release path" at the bottom of
//! this file. Caching is what stayed out; ignoring the release path did not.

use std::path::Path;

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repo-relative file, panicking with the path on failure.
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The workflows whose jobs run on GitHub-hosted runners without a container.
///
/// Derived rather than listed: any workflow that installs system packages and
/// never declares a `container:` is one of these by construction, so a new
/// workflow is covered the day it lands instead of the day someone remembers
/// to add it here. A gate that hardcodes its subjects cannot see a new one.
fn hosted_workflows_installing_packages() -> Vec<String> {
    let dir = repo().join(".github/workflows");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read .github/workflows") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("workflow file name")
            .to_string();
        let text = std::fs::read_to_string(&path).expect("read workflow");
        // A workflow that never installs anything has nothing to convert.
        if !text.contains("apt-get install") && !text.contains("system-deps") {
            continue;
        }
        // Container jobs install as root against a pinned image; `actions/cache`
        // does not apply to them. See the module note on `release.yml`.
        if text.contains("container:") {
            continue;
        }
        out.push(name);
    }
    out.sort();
    out
}

/// A hosted job must not shell out to `apt-get install` on the common path.
///
/// This is the failure that cost the 0.5.118 tag two re-run cycles. The
/// assertion is on the *absence of the fetch*, not on the presence of a
/// guard: the guard was already there and was structurally unable to fire.
#[test]
fn no_hosted_workflow_installs_system_packages_from_the_archives() {
    let mut offenders: Vec<String> = Vec::new();
    for wf in hosted_workflows_installing_packages() {
        let text = read(&format!(".github/workflows/{wf}"));
        for (i, line) in text.lines().enumerate() {
            // A comment that mentions the command is prose, not a fetch. Left
            // scanned-but-skipped rather than stripped, because the history of
            // WHY these steps look the way they do lives in those comments.
            if line.trim_start().starts_with('#') {
                continue;
            }
            if line.contains("apt-get install") {
                offenders.push(format!("{wf}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these hosted CI steps fetch system packages from the Ubuntu archives \
         on every run, which is what hung for 15 minutes and cancelled the \
         0.5.118 CI run.\nUse the shared local-first action instead:\n  \
         - uses: ./.github/actions/system-deps\n    with:\n      packages: \
         libpcap-dev libasound2-dev\n\n{}",
        offenders.join("\n")
    );
}

/// No local action interpolates an expression into a shell script body.
///
/// `${{ ... }}` is substituted as TEXT before bash ever sees the script, so a
/// value containing `;` or `$(...)` becomes CODE rather than data. Passing it
/// through `env:` instead makes bash treat it as a value and nothing else.
///
/// Flagged on `.github/actions/system-deps/action.yml` by an external scanner
/// after it shipped, and the scanner was right even though nothing untrusted
/// can reach that input today -- the only callers are workflow files in this
/// repository. A composite action is reusable by definition, so "not currently
/// reachable" is a property of today's callers, not of the action. This gate
/// holds the pattern rather than the reachability argument, because the
/// reachability argument is the part that changes without anyone noticing.
#[test]
fn no_local_action_interpolates_an_expression_into_a_shell_script() {
    let dir = repo().join(".github/actions");
    if !dir.exists() {
        return;
    }
    let mut offenders = Vec::new();
    let mut scanned = 0usize;

    for entry in std::fs::read_dir(&dir).expect("read .github/actions") {
        let action = entry.expect("dir entry").path().join("action.yml");
        if !action.exists() {
            continue;
        }
        scanned += 1;
        let name = action
            .strip_prefix(repo())
            .unwrap_or(&action)
            .display()
            .to_string();
        let text = std::fs::read_to_string(&action).expect("read action");

        // Walk the file tracking whether we are inside a `run: |` block. Only
        // those bodies execute; `env:`, `key:` and `if:` are evaluated by the
        // runner, where an expression is the intended mechanism.
        let mut in_run = false;
        let mut run_indent = 0usize;
        for (i, line) in text.lines().enumerate() {
            let indent = line.len() - line.trim_start().len();
            if in_run && !line.trim().is_empty() && indent <= run_indent {
                in_run = false;
            }
            if line.trim_start().starts_with("run: |") {
                in_run = true;
                run_indent = indent;
                continue;
            }
            if in_run && line.contains("${{") {
                offenders.push(format!("{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }

    assert!(
        scanned > 0,
        "no action.yml files were scanned; this gate is checking nothing"
    );
    assert!(
        offenders.is_empty(),
        "these lines interpolate a workflow expression directly into a shell \
         script, where the value becomes code rather than data. Pass it through \
         the step's `env:` block and reference it as a shell variable:\n  \
         env:\n    PACKAGES: ${{{{ inputs.packages }}}}\n  run: |\n    \
         for p in $PACKAGES; do ...\n\n{}",
        offenders.join("\n")
    );
}

/// The shared action must install from the cache without touching the network.
///
/// The negative control for the rule above. An action that merely wraps the
/// same `apt-get install` would satisfy the first test while changing nothing
/// about the failure it exists to prevent, so the cache-hit path is asserted
/// to use `dpkg -i` — which cannot reach a network — and the cold path is
/// asserted to be bounded by a timeout.
#[test]
fn the_shared_action_installs_from_cache_and_bounds_the_cold_path() {
    let action = read(".github/actions/system-deps/action.yml");

    assert!(
        action.contains("dpkg -i"),
        "the cache-hit path must install the .deb files directly, which \
         performs no network access; without it the action is just apt-get \
         with extra steps:\n{action}"
    );
    assert!(
        action.contains("actions/cache"),
        "the .deb files must be restored from actions/cache, or every run \
         repopulates them from the archives:\n{action}"
    );
    assert!(
        action.contains("timeout "),
        "the cold-cache path still reaches the archives, so it must be bounded \
         by a timeout -- an unbounded apt-get is exactly what consumed 15 \
         minutes before being cancelled:\n{action}"
    );
}

/// The image scanner's vulnerability DB must be cached, and must be able to
/// fall back when the download fails.
///
/// The second external fetch that failed on 2026-08-20. Trivy pulls a ~60 MB
/// DB from `mirror.gcr.io`; the download stalled, and the Docker job died with
/// the image already built and smoke-tested. A cache alone is not enough --
/// without `restore-keys` a cold key on a day the mirror is down leaves the
/// job in exactly the same position.
#[test]
fn the_image_scanner_caches_its_vulnerability_db_with_a_fallback() {
    let docker = read(".github/workflows/docker.yml");

    assert!(
        docker.contains("TRIVY_CACHE_DIR"),
        "the scanner must be pointed at a cached DB directory, or it \
         re-downloads ~60 MB on every run:\n{docker}"
    );
    assert!(
        docker.contains("key: trivy-db-"),
        "the DB cache needs a key that changes over time; a fixed key is a \
         vulnerability DB that never refreshes, which is a scan that quietly \
         stops finding things"
    );
    assert!(
        docker.contains("restore-keys: trivy-db-"),
        "without restore-keys, the first run of a day on which the mirror is \
         down has no DB to fall back to and the job dies -- which is the exact \
         failure this cache exists to prevent"
    );
}

/// A scan that never ran must not be reported as a scan that failed.
///
/// `if: always()` on the SARIF upload turned one infrastructure failure into
/// two: the DB download stalled, no report was written, and the upload failed
/// with `Path does not exist: trivy.sarif`. Uploading findings when the scan
/// FINDS something is the intent; uploading a file that was never created is
/// not.
#[test]
fn the_sarif_upload_does_not_fail_when_the_scan_wrote_nothing() {
    let docker = read(".github/workflows/docker.yml");
    assert!(
        docker.contains("always() && hashFiles('trivy.sarif') != ''"),
        "the SARIF upload must be guarded on the report existing, or a scan \
         that died before writing one produces a second, misleading failure \
         that points at the upload rather than the download:\n{docker}"
    );
}

/// Every converted workflow must actually reference the shared action.
///
/// Deleting an apt step passes the first test as surely as converting it does.
/// This asserts the dependency is still installed, by the intended route.
#[test]
fn converted_workflows_reference_the_shared_action() {
    for wf in hosted_workflows_installing_packages() {
        let text = read(&format!(".github/workflows/{wf}"));
        assert!(
            text.contains("./.github/actions/system-deps"),
            "{wf} needs system packages but does not use \
             ./.github/actions/system-deps -- if its dependency was simply \
             deleted, the job builds against whatever the runner happens to \
             carry"
        );
    }
}

// ── The release path ────────────────────────────────────────────────────────
//
// Measured over one session on 2026-08-21, four builds failed on a fetch and
// none on the code. The one that mattered was the 0.5.120 RELEASE build: it
// died on the netmap headers pulled from `raw.githubusercontent.com` inside
// the musl cross image, so `Create Release` and the Homebrew bump -- both
// `needs: build` -- were skipped and the v0.5.120 tag existed, public, with no
// artefacts behind it until the job was re-run by hand.
//
// That is the asymmetry the gates below encode. A CI fetch failing costs a
// re-run; a RELEASE fetch failing costs a published tag that promises files
// nobody can download. The inputs are all fixed and versioned -- a commit, a
// release tarball -- so there is no reason for either to be fetched without a
// bound, a retry, and a checksum.

/// The cross-compilation images the musl release artifacts are built in.
///
/// Derived from the directory rather than listed, for the same reason
/// `hosted_workflows_installing_packages` is: a third musl target gets these
/// gates the day its Dockerfile lands, not the day someone remembers it.
fn cross_dockerfiles() -> Vec<String> {
    let dir = repo().join("docker/cross");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read docker/cross") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("file name")
            .to_string();
        if name.starts_with("Dockerfile") {
            out.push(format!("docker/cross/{name}"));
        }
    }
    out.sort();
    out
}

/// Join a Dockerfile's `\` continuations into one string per instruction.
///
/// Reading the file line by line is not how DOCKER reads it, and the
/// difference is the whole of the 0.5.120 defect: fetching and building were
/// ONE instruction, so the failure message quoted the entire `&&` chain and
/// led with `apt-get install` -- a command that had succeeded. Comment lines
/// are dropped mid-continuation, which is also what the Docker parser does.
fn dockerfile_instructions(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start = 0usize;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        if line.trim_start().starts_with('#') {
            continue;
        }
        if cur.is_empty() {
            if line.trim().is_empty() {
                continue;
            }
            start = i + 1;
        }
        let continued = line.ends_with('\\');
        cur.push_str(line.trim_end_matches('\\'));
        cur.push(' ');
        if !continued {
            out.push((start, cur.trim().to_string()));
            cur.clear();
        }
    }
    if !cur.trim().is_empty() {
        out.push((start, cur.trim().to_string()));
    }
    out
}

/// Is this line a `::error::` annotation rather than a command?
///
/// The whole point of these changes is that a failed fetch NAMES the command
/// that failed, so the messages say `apt-get` and `curl` on purpose. Without
/// this, the gates below would flag their own remedy: an error line reading
/// "curl could not download ..." is prose about curl, not an invocation of it.
fn is_annotation(line: &str) -> bool {
    line.contains("::error::") || line.contains("::warning::")
}

/// Every URL the cross images download is verified against a pinned checksum.
///
/// Not defensive padding: these inputs cannot vary. The netmap headers are
/// pinned to a commit and libpcap to a release tarball, so each host has
/// exactly one correct answer and until 0.5.120 nothing checked which one it
/// gave. A substituted or truncated header would have surfaced as a compiler
/// error deep inside libpcap rather than as "the download is wrong", which is
/// the confusing-build-error case a checksum turns into a clear one.
///
/// The count of checksums is compared against the count of URLs in the same
/// instruction, so adding a fourth download without a pin fails here rather
/// than appearing to inherit the previous one.
#[test]
fn every_download_in_the_cross_images_is_pinned_by_a_checksum() {
    let files = cross_dockerfiles();
    assert!(
        !files.is_empty(),
        "no cross Dockerfiles were scanned; this gate is checking nothing"
    );
    let mut offenders = Vec::new();
    let mut pinned = 0usize;

    for f in &files {
        let text = read(f);
        assert!(
            text.contains("sha256sum -c"),
            "{f} downloads pinned inputs but never verifies one; a checksum \
             that is recorded and not checked is a comment"
        );
        for (line, instr) in dockerfile_instructions(&text) {
            let urls = instr.matches("https://").count() + instr.matches("http://").count();
            if urls == 0 {
                continue;
            }
            let sums = instr.matches("_SHA256}").count();
            if !instr.contains("fetch-pinned") || sums != urls {
                offenders.push(format!(
                    "{f}:{line}: {urls} download(s) but {sums} checksum(s)\n    {instr}"
                ));
            }
            pinned += sums;
        }
    }

    assert!(
        offenders.is_empty(),
        "these downloads in the release cross images are not pinned by a \
         checksum. Fetch them through the image's `fetch-pinned` helper, \
         passing the sha256 as its third argument:\n  fetch-pinned \"<url>\" \
         \"<dest>\" \"${{THING_SHA256}}\"\n\n{}",
        offenders.join("\n")
    );
    assert!(
        pinned >= 4,
        "expected at least the three netmap headers and the libpcap tarball \
         to be checksummed, found {pinned}; if a download was deleted rather \
         than pinned, the image builds against something else"
    );
}

/// A stalled mirror costs minutes, not the job's whole 45.
///
/// The negative control for the checksum gate: a helper that verifies bytes it
/// waited forever for is no better than the bare `wget` it replaced. The
/// 0.5.118 CI failure was a fifteen-minute hang, not an error, and the fix
/// that worked there was a `timeout` -- the same shape `system-deps` uses on
/// its cold path.
///
/// Every assertion here is made against the INVOCATION line, never the file.
/// The first draft asserted `text.contains("--tries=")` over the whole file,
/// and mutation-testing caught it: deleting `--tries=5` from the wget call
/// left the comment block that explains `--tries=5` in place, and the gate
/// stayed green. These files document their own flags, so a whole-file search
/// is satisfied by prose ABOUT a retry rather than by a retry.
#[test]
fn every_download_in_the_cross_images_is_bounded_and_retried() {
    for f in &cross_dockerfiles() {
        let text = read(f);
        let mut wget_calls = 0usize;
        let mut apt_calls = 0usize;

        for line in text.lines() {
            if line.trim_start().starts_with('#') {
                continue;
            }

            // `wget -`, not `wget`: the apt line installs a PACKAGE called
            // wget, and matching the bare word would let that line answer for
            // a download it says nothing about.
            if line.contains("wget -") {
                wget_calls += 1;
                let w = line.find("wget -").expect("just matched");
                // `timeout` must precede wget to bound it. A `--timeout=`
                // flag bounds one stalled read inside wget; it does not bound
                // wget, and the fifteen-minute 0.5.118 hang was not an error.
                assert!(
                    matches!(line.find("timeout "), Some(t) if t < w),
                    "{f} runs wget without an outer `timeout`, so a host that \
                     accepts the connection and then trickles holds the \
                     release build until the job's timeout-minutes kills it \
                     with no useful message:\n  {}",
                    line.trim()
                );
                assert!(
                    line.contains("--tries="),
                    "{f} does not retry this download; a single dropped \
                     connection fails a build that has a public tag behind \
                     it:\n  {}",
                    line.trim()
                );
                assert!(
                    line.contains("--waitretry="),
                    "{f} retries this download without backing off, which \
                     turns one unavailable host into five requests in as many \
                     seconds and no more chance of success:\n  {}",
                    line.trim()
                );
            }

            if line.contains("apt-get ") {
                apt_calls += 1;
                assert!(
                    line.contains("Acquire::Retries"),
                    "{f} reaches the distribution archives without apt \
                     retries -- the archives are the host that hung for \
                     fifteen minutes on 2026-08-20:\n  {}",
                    line.trim()
                );
                assert!(
                    line.contains("timeout "),
                    "{f} reaches the distribution archives unbounded:\n  {}",
                    line.trim()
                );
            }
        }

        assert!(
            wget_calls > 0 && apt_calls > 0,
            "{f}: found {wget_calls} download(s) and {apt_calls} package \
             install(s); a step deleted rather than bounded builds the image \
             against something else"
        );
    }
}

/// A failed fetch must not be quoted as a failed build.
///
/// THE defect from 0.5.120, stated as a property. Docker prints the whole
/// failing `RUN` instruction, so an instruction that both downloads and
/// compiles produces a message whose first command is `apt-get install` when
/// what actually failed was a `wget` forty lines later. Whoever reads it goes
/// looking at the package list.
///
/// Splitting them is the fix, and this is the gate that keeps them split.
#[test]
fn no_cross_image_instruction_mixes_a_download_with_a_build() {
    // Commands that compile or link. If one of these shares an instruction
    // with a download, the log cannot say which half failed.
    const BUILD_COMMANDS: &[&str] = &["./configure", "make -j", "make install", "ar t "];
    let mut offenders = Vec::new();
    let mut scanned = 0usize;

    for f in &cross_dockerfiles() {
        let text = read(f);
        for (line, instr) in dockerfile_instructions(&text) {
            if !instr.starts_with("RUN ") {
                continue;
            }
            scanned += 1;
            let downloads = instr.contains("fetch-pinned \"")
                || instr.contains("wget ")
                || instr.contains("curl ")
                || instr.contains("apt-get ");
            let builds = BUILD_COMMANDS.iter().any(|c| instr.contains(c));
            if downloads && builds {
                offenders.push(format!("{f}:{line}: {instr}"));
            }
        }
    }

    assert!(
        scanned > 0,
        "no RUN instructions were scanned; this gate is checking nothing"
    );
    assert!(
        offenders.is_empty(),
        "these RUN instructions both download and build. Docker quotes the \
         whole instruction when it fails, so the message names the first \
         command in the chain rather than the one that failed -- which is \
         exactly how the 0.5.120 release failure came to blame `apt-get` for \
         a `wget` that could not reach raw.githubusercontent.com. Put the \
         downloads in their own RUN.\n\n{}",
        offenders.join("\n")
    );
}

/// Every package install in the release workflow is bounded by a timeout.
///
/// `release.yml` cannot adopt `system-deps`, and that part of the exclusion
/// recorded at the top of this file still holds: its builds run as root inside
/// pinned containers where the package set is multiarch and `actions/cache`
/// has no meaning. What did not survive contact with 0.5.120 is the idea that
/// the exclusion could simply wait. Bounding is available even where caching
/// is not, and a release fetch failing is strictly worse than a CI fetch
/// failing because the tag is already public by the time it happens.
#[test]
fn every_package_install_in_the_release_workflow_is_bounded() {
    let text = read(".github/workflows/release.yml");
    assert!(
        text.contains("apt-get install"),
        "release.yml no longer installs anything; if the dependency was \
         deleted rather than bounded, the builds link against whatever the \
         container happens to carry"
    );
    let mut offenders = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with('#') || is_annotation(line) {
            continue;
        }
        // Every line that INVOKES apt-get, not only the ones naming a
        // subcommand. Mutation-testing caught the narrower version: the
        // bounded wrapper reads `timeout "$secs" apt-get ... "$@"`, so
        // deleting its `timeout` left a file whose only `apt-get install`
        // text was at a call site that goes through the wrapper, and the
        // gate stayed green while every install had become unbounded.
        //
        // `command -v apt-get` asks whether apt EXISTS. It reaches no
        // archive and cannot hang, so it is the one exemption.
        if !line.contains("apt-get ") || line.contains("command -v apt-get") {
            continue;
        }
        if !line.contains("timeout ") {
            offenders.push(format!("release.yml:{}: {}", i + 1, line.trim()));
        }
    }
    assert!(
        offenders.is_empty(),
        "these release steps reach the distribution archives unbounded. An \
         `apt-get install libpcap-dev` that hung for fifteen minutes is what \
         cancelled the 0.5.118 CI run; the same call in a release job holds a \
         build that a public tag is waiting on. Wrap it:\n  timeout 600 \
         apt-get -o Acquire::Retries=5 install -y <pkgs>\n\n{}",
        offenders.join("\n")
    );
}

/// Every direct download in the release workflow retries and is checksummed.
///
/// The bpf-linker tarball was already verified against a recorded sha256 --
/// this holds that, and adds the retry it lacked. One dropped connection to
/// `github.com` here fails a gnu build, and every gnu artifact plus both
/// packages ship from that job.
#[test]
fn every_direct_download_in_the_release_workflow_retries_and_is_checksummed() {
    let text = read(".github/workflows/release.yml");
    let mut curls = 0usize;
    let mut offenders = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with('#') || is_annotation(line) || !line.contains("curl ") {
            continue;
        }
        curls += 1;
        if !line.contains("--retry") {
            offenders.push(format!("release.yml:{}: {}", i + 1, line.trim()));
        }
    }
    assert!(
        curls > 0,
        "no curl invocations were scanned; this gate is checking nothing"
    );
    assert!(
        offenders.is_empty(),
        "these release downloads do not retry:\n{}",
        offenders.join("\n")
    );
    assert!(
        text.contains("sha256sum -c"),
        "a release download is no longer verified against a pinned checksum; \
         an artifact built from bytes nobody checked is attested and \
         published all the same"
    );
}
