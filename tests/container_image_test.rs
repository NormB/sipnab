// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The container image: what the `Dockerfile` puts in it and how
//! `.github/workflows/docker.yml` publishes it.
//!
//! Four defects, one group of tests each.
//!
//! - OPS-15. The runtime stage had no CA bundle, so a TLS HEP sender in the
//!   image needed `--hep-tls-ca` even for a collector whose certificate a
//!   public CA signed. The bundle paths sipnab reads are read here from
//!   `src/tls_files.rs`, not copied.
//! - OPS-4. The image's default user `sipnab` could not capture, even with
//!   `--cap-add NET_RAW --cap-add NET_ADMIN`. Docker adds those capabilities
//!   to the bounding set, but a process that is not root loses its permitted
//!   and effective sets at `execve` unless the file it executes carries file
//!   capabilities, and the binary carried none. The fix gives the binary
//!   permitted-only file capabilities (`+p`) and has sipnab raise them into
//!   its effective set at startup. The effective bit (`+ep`) is refused: with
//!   it, `execve` fails with `EPERM` whenever the bounding set lacks one of the
//!   named capabilities, and Docker's default set lacks `CAP_NET_ADMIN`, so
//!   even `docker run <image> --version` would fail.
//! - OPS-2. `:latest` followed `main`. It now moves only on a release tag;
//!   `:edge` follows `main`.
//! - OPS-3. The image was `linux/amd64` only. Each platform is now built on a
//!   runner of its own architecture, smoke-tested and scanned there, pushed by
//!   digest, and joined into one manifest list.
//!
//! The readers here are line-based. Each one has a test of its own on
//! synthetic input, so a reader that stops matching fails rather than passing
//! everything.

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::PathBuf;

type TestError = Box<dyn std::error::Error>;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(repo().join(rel)).map_err(|e| format!("read {rel}: {e}"))?)
}

// ── Dockerfile reader ────────────────────────────────────────────────────────

/// One build stage: its base image, its name, and its instructions with
/// continuation lines joined and comment lines dropped.
#[derive(Debug)]
struct Stage {
    base: String,
    name: Option<String>,
    instructions: Vec<String>,
}

impl Stage {
    /// The arguments of every instruction `keyword` (upper case), in order.
    fn args<'a>(&'a self, keyword: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.instructions.iter().filter_map(move |i| {
            let (k, rest) = i.split_once(char::is_whitespace)?;
            k.eq_ignore_ascii_case(keyword).then_some(rest.trim())
        })
    }

    /// The shell commands of every `RUN`, split on `&&` and `;`, each with the
    /// working directory in force when it runs.
    fn run_commands(&self) -> Vec<(String, String)> {
        let mut workdir = String::from("/");
        let mut out = Vec::new();
        for i in &self.instructions {
            let Some((k, rest)) = i.split_once(char::is_whitespace) else {
                continue;
            };
            if k.eq_ignore_ascii_case("WORKDIR") {
                workdir = absolute(&workdir, rest.trim());
            } else if k.eq_ignore_ascii_case("RUN") {
                for part in rest.split("&&").flat_map(|p| p.split(';')) {
                    let cmd = part.trim();
                    if !cmd.is_empty() {
                        out.push((workdir.clone(), cmd.to_string()));
                    }
                }
            }
        }
        out
    }

    /// The packages every `apt-get install` / `apt install` in this stage
    /// names, versions stripped.
    fn apt_packages(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (_, cmd) in self.run_commands() {
            let words: Vec<&str> = cmd.split_whitespace().collect();
            let Some(at) = words.iter().position(|w| *w == "install") else {
                continue;
            };
            if !words[..at].iter().any(|w| *w == "apt-get" || *w == "apt") {
                continue;
            }
            for w in &words[at + 1..] {
                if !w.starts_with('-') {
                    out.insert(w.split('=').next().unwrap_or(w).to_string());
                }
            }
        }
        out
    }
}

/// `path` resolved against `dir` when it is relative.
fn absolute(dir: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{path}", dir.trim_end_matches('/'))
    }
}

/// The stages of a Dockerfile, in order.
fn stages(dockerfile: &str) -> Vec<Stage> {
    let mut logical = Vec::new();
    let mut pending = String::new();
    for line in dockerfile.lines() {
        let t = line.trim();
        if t.starts_with('#') || (t.is_empty() && pending.is_empty()) {
            continue;
        }
        if let Some(head) = t.strip_suffix('\\') {
            pending.push_str(head);
            pending.push(' ');
            continue;
        }
        pending.push_str(t);
        logical.push(std::mem::take(&mut pending));
    }
    if !pending.is_empty() {
        logical.push(pending);
    }
    let mut out: Vec<Stage> = Vec::new();
    for ins in logical {
        let words: Vec<&str> = ins.split_whitespace().collect();
        if words
            .first()
            .is_some_and(|w| w.eq_ignore_ascii_case("FROM"))
        {
            let rest: Vec<&str> = words[1..]
                .iter()
                .copied()
                .filter(|w| !w.starts_with("--"))
                .collect();
            let name = rest
                .iter()
                .position(|w| w.eq_ignore_ascii_case("AS"))
                .and_then(|i| rest.get(i + 1))
                .map(|s| (*s).to_string());
            out.push(Stage {
                base: rest.first().map(|s| (*s).to_string()).unwrap_or_default(),
                name,
                instructions: Vec::new(),
            });
        } else if let Some(stage) = out.last_mut() {
            stage.instructions.push(ins);
        }
    }
    out
}

/// The stage the image is made of: the last one.
fn runtime(stages: &[Stage]) -> Result<&Stage, TestError> {
    Ok(stages.last().ok_or("the Dockerfile has no stage")?)
}

// ── OPS-15: the CA bundle ────────────────────────────────────────────────────

/// The paths in `src/tls_files.rs`'s `SYSTEM_CA_BUNDLES`, read from the
/// source so this test cannot hold a stale copy of the list.
fn system_ca_bundles(source: &str) -> Result<Vec<String>, TestError> {
    let start = source
        .find("const SYSTEM_CA_BUNDLES: &[&str] = &[")
        .ok_or("src/tls_files.rs has no `const SYSTEM_CA_BUNDLES: &[&str] = &[`")?;
    let body = &source[start..];
    let end = body.find("];").ok_or("SYSTEM_CA_BUNDLES is not closed")?;
    let mut out = Vec::new();
    for line in body[..end].lines().skip(1) {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if let Some(lit) = t.strip_prefix('"').and_then(|r| r.split_once('"')) {
            out.push(lit.0.to_string());
        }
    }
    Ok(out)
}

/// The bundle file a CA package installs on a base image's distribution, for
/// the distributions this Dockerfile could plausibly use. `None` for any other
/// pair, so a base or package change fails the test rather than being
/// guessed at.
fn bundle_installed_by(base: &str, package: &str) -> Option<&'static str> {
    let image = base.split(['@', ':']).next().unwrap_or(base);
    let image = image.rsplit('/').next().unwrap_or(image);
    match (image, package) {
        // Debian's ca-certificates writes the bundle in its postinst
        // (`update-ca-certificates`).
        ("debian" | "ubuntu", "ca-certificates") => Some("/etc/ssl/certs/ca-certificates.crt"),
        _ => None,
    }
}

/// The CA bundle path a stage provides that sipnab reads, or why none.
fn runtime_bundle_problem(stage: &Stage, sipnab_paths: &[String]) -> Option<String> {
    let provided: Vec<&str> = stage
        .apt_packages()
        .iter()
        .filter_map(|p| bundle_installed_by(&stage.base, p))
        .collect();
    if provided.is_empty() {
        return Some(format!(
            "the runtime stage (FROM {}) installs no CA package this test knows \
             the bundle path of; its packages are {:?}",
            stage.base,
            stage.apt_packages()
        ));
    }
    if provided.iter().any(|p| sipnab_paths.iter().any(|s| s == p)) {
        return None;
    }
    Some(format!(
        "the runtime stage provides {provided:?}, and sipnab reads only \
         {sipnab_paths:?}"
    ))
}

/// GIVEN the Dockerfile's runtime stage and the bundle paths sipnab reads
/// WHEN the stage's packages are read
/// THEN one of them installs a bundle at one of those paths.
#[test]
fn the_runtime_stage_installs_a_ca_bundle_at_a_path_sipnab_reads() -> Result<(), TestError> {
    let paths = system_ca_bundles(&read("src/tls_files.rs")?)?;
    let dockerfile = read("Dockerfile")?;
    let all = stages(&dockerfile);
    let stage = runtime(&all)?;
    assert_eq!(
        stage.name.as_deref(),
        Some("runtime"),
        "the last stage is not the `runtime` stage docker.yml refuses to cache"
    );
    if let Some(why) = runtime_bundle_problem(stage, &paths) {
        return Err(format!(
            "{why}. Without a CA bundle a TLS HEP sender in the image needs \
             --hep-tls-ca even for a public CA (OPS-15)"
        )
        .into());
    }
    Ok(())
}

/// GIVEN a Dockerfile that installs ca-certificates in the builder only
/// WHEN the runtime stage is checked
/// THEN it is refused: the builder is not shipped.
#[test]
fn a_ca_bundle_in_the_builder_only_is_refused() -> Result<(), TestError> {
    let paths = vec!["/etc/ssl/certs/ca-certificates.crt".to_string()];
    let text = "FROM rust:1 AS builder\n\
                RUN apt-get update && apt-get install -y ca-certificates\n\
                FROM debian:trixie-slim@sha256:00 AS runtime\n\
                RUN apt-get install -y libpcap0.8t64\n";
    let all = stages(text);
    let why = runtime_bundle_problem(runtime(&all)?, &paths).ok_or("accepted")?;
    assert!(why.contains("installs no CA package"), "{why}");
    Ok(())
}

/// GIVEN a runtime stage whose bundle lands at a path sipnab does not read
/// WHEN it is checked
/// THEN it is refused, naming both.
#[test]
fn a_bundle_at_a_path_sipnab_does_not_read_is_refused() -> Result<(), TestError> {
    let text = "FROM debian:trixie-slim AS runtime\n\
                RUN apt-get install -y ca-certificates\n";
    let all = stages(text);
    let why = runtime_bundle_problem(runtime(&all)?, &["/etc/pki/tls/certs/ca-bundle.crt".into()])
        .ok_or("accepted")?;
    assert!(why.contains("/etc/ssl/certs/ca-certificates.crt"), "{why}");
    Ok(())
}

/// GIVEN the source list
/// WHEN it is read
/// THEN every entry is an absolute path, the comment lines are skipped, and
/// the reader found the whole list.
#[test]
fn the_bundle_list_is_read_from_the_source() -> Result<(), TestError> {
    let paths = system_ca_bundles(&read("src/tls_files.rs")?)?;
    assert!(
        paths.len() >= 2,
        "read {paths:?} from SYSTEM_CA_BUNDLES; the reader has stopped matching"
    );
    assert!(paths.iter().all(|p| p.starts_with('/')), "{paths:?}");
    let synthetic = "const SYSTEM_CA_BUNDLES: &[&str] = &[\n    // \"/not/this\"\n    \"/a\",\n    \"/b\",\n];\n";
    assert_eq!(
        system_ca_bundles(synthetic)?,
        vec!["/a", "/b"],
        "the bundle list is read in source order"
    );
    Ok(())
}

/// GIVEN a `RUN` that installs with flags, a version and a continuation
/// WHEN its packages are read
/// THEN flags are skipped, the version is stripped, and the commands after
/// `&&` are not read as packages.
#[test]
fn the_package_reader_handles_flags_versions_and_continuations() -> Result<(), TestError> {
    let text = "FROM debian:trixie-slim AS runtime\n\
                RUN apt-get update && apt-get upgrade -y \\\n \
                && apt-get install -y --no-install-recommends a b=1.2 \\\n \
                && rm -rf /var/lib/apt/lists/*\n\
                RUN echo install x\n";
    let all = stages(text);
    let got: Vec<String> = runtime(&all)?.apt_packages().into_iter().collect();
    assert_eq!(
        got,
        vec!["a", "b"],
        "one package per name, flags and versions dropped"
    );
    Ok(())
}

// ── OPS-4: capture as the image's default user ───────────────────────────────

/// What is wrong with the way the Dockerfile gives the shipped binary its
/// capture capabilities, given the capability names sipnab raises.
///
/// The rule: a `setcap <names>+p <file>` in some stage, on the file the
/// runtime stage copies from that stage; after the last command that rewrites
/// that file (`strip` replaces the file and drops its extended attributes);
/// in a stage that installs `libcap2-bin`; with nothing in the runtime stage
/// that touches the copy afterwards (`chown` clears file capabilities); and a
/// runtime `USER` that is not root, which is the case the capabilities exist
/// for.
fn file_caps_problems(dockerfile: &str, names: &str) -> Vec<String> {
    let all = stages(dockerfile);
    let Some(rt) = all.last() else {
        return vec!["no stage".into()];
    };
    let want = format!("{names}+p");
    let mut problems = Vec::new();
    let mut found = None;
    for stage in &all[..all.len().saturating_sub(1)] {
        let cmds = stage.run_commands();
        for (i, (dir, cmd)) in cmds.iter().enumerate() {
            let words: Vec<&str> = cmd.split_whitespace().collect();
            if words.first() != Some(&"setcap") {
                continue;
            }
            let (Some(caps), Some(file)) = (words.get(1), words.get(2)) else {
                problems.push(format!("`{cmd}` names no capabilities or no file"));
                continue;
            };
            let file = absolute(dir, file);
            found = Some(file.clone());
            if *caps != want {
                problems.push(format!(
                    "the binary gets `{caps}`, not `{want}`. An effective bit makes \
                     execve fail with EPERM whenever the bounding set lacks one of \
                     the named capabilities, and Docker's default set lacks \
                     CAP_NET_ADMIN"
                ));
            }
            let rewritten_later = cmds[i + 1..].iter().any(|(d, c)| {
                let w: Vec<&str> = c.split_whitespace().collect();
                w.first()
                    .is_some_and(|p| *p == "strip" || p.ends_with("-strip"))
                    && w.iter().skip(1).any(|a| absolute(d, a) == file)
            });
            if rewritten_later {
                problems.push(format!(
                    "`strip` rewrites {file} after `setcap`, which drops its file \
                     capabilities"
                ));
            }
            if !stage.apt_packages().contains("libcap2-bin") {
                problems.push(format!(
                    "the stage that runs setcap ({:?}) does not install libcap2-bin",
                    stage.name
                ));
            }
            let copied = rt.args("COPY").find_map(|a| {
                let w: Vec<&str> = a.split_whitespace().collect();
                let from = w.iter().find_map(|x| x.strip_prefix("--from="))?;
                (Some(from) == stage.name.as_deref() && w.contains(&file.as_str()))
                    .then(|| w.last().map(|d| (*d).to_string()))
                    .flatten()
            });
            match copied {
                None => problems.push(format!(
                    "the runtime stage does not COPY {file} from the stage that \
                     set its capabilities"
                )),
                Some(dest) => {
                    let copy_at = rt.instructions.iter().position(|i| {
                        i.starts_with("COPY") && i.contains(&file) && i.ends_with(&dest)
                    });
                    let touched = copy_at.is_some_and(|at| {
                        rt.instructions[at + 1..]
                            .iter()
                            .any(|i| i.starts_with("RUN") && i.contains(&dest))
                    });
                    if touched {
                        problems.push(format!(
                            "a RUN after the COPY touches {dest}; chown and a rewrite \
                             both clear file capabilities"
                        ));
                    }
                }
            }
        }
    }
    if found.is_none() {
        problems.push(
            "no stage runs setcap, so the binary has no file capabilities and a \
             non-root user loses every capability Docker grants at execve"
                .into(),
        );
    }
    match rt.args("USER").last() {
        Some(u) if u != "root" && u != "0" && !u.starts_with("0:") => {}
        other => problems.push(format!(
            "the runtime USER is {other:?}; the capabilities are for a non-root user"
        )),
    }
    problems
}

/// GIVEN the Dockerfile and the capability names sipnab raises at startup
/// WHEN the binary's file capabilities are read
/// THEN they are those names, permitted only, set after the strip, and copied
/// unchanged into a runtime stage that runs as a non-root user.
#[test]
fn the_image_binary_carries_permitted_only_capture_caps() -> Result<(), TestError> {
    let problems = file_caps_problems(&read("Dockerfile")?, sipnab::privilege::CAPTURE_CAP_NAMES);
    assert!(
        problems.is_empty(),
        "the image's default user cannot capture (OPS-4):\n  {}",
        problems.join("\n  ")
    );
    Ok(())
}

/// The synthetic Dockerfile the refusals below vary.
const GOOD: &str = "FROM rust:1 AS builder\n\
                    RUN apt-get install -y libpcap-dev libcap2-bin\n\
                    WORKDIR /build\n\
                    RUN cargo build --release\n\
                    RUN strip target/release/sipnab \\\n \
                    && setcap cap_net_raw,cap_net_admin+p /build/target/release/sipnab\n\
                    FROM debian:trixie-slim AS runtime\n\
                    RUN useradd -r sipnab\n\
                    COPY --from=builder /build/target/release/sipnab /usr/local/bin/sipnab\n\
                    USER sipnab\n";

#[test]
fn the_rule_accepts_the_synthetic_good_dockerfile() {
    assert_eq!(
        file_caps_problems(GOOD, "cap_net_raw,cap_net_admin"),
        Vec::<String>::new(),
        "the synthetic good Dockerfile has no problem"
    );
}

/// GIVEN `+ep`
/// WHEN the rule reads it
/// THEN it is refused: the image would not start under Docker's default
/// capabilities.
#[test]
fn an_effective_bit_in_the_file_caps_is_refused() -> Result<(), TestError> {
    let text = GOOD.replace("cap_net_admin+p", "cap_net_admin+ep");
    let p = file_caps_problems(&text, "cap_net_raw,cap_net_admin");
    assert!(p.iter().any(|m| m.contains("EPERM")), "{p:?}");
    Ok(())
}

/// GIVEN a strip after the setcap, relative path against an absolute one
/// WHEN the rule reads it
/// THEN it is refused.
#[test]
fn a_strip_after_the_setcap_is_refused() -> Result<(), TestError> {
    let text = GOOD.replace(
        "RUN strip target/release/sipnab \\\n && setcap cap_net_raw,cap_net_admin+p /build/target/release/sipnab\n",
        "RUN setcap cap_net_raw,cap_net_admin+p /build/target/release/sipnab\nRUN strip target/release/sipnab\n",
    );
    assert_ne!(text, GOOD, "the synthetic replacement did not apply");
    let p = file_caps_problems(&text, "cap_net_raw,cap_net_admin");
    assert!(p.iter().any(|m| m.contains("strip")), "{p:?}");
    Ok(())
}

/// GIVEN no setcap at all, the Dockerfile this defect was found in
/// WHEN the rule reads it
/// THEN it is refused.
#[test]
fn no_file_caps_at_all_is_refused() -> Result<(), TestError> {
    let text = GOOD.replace(
        " \\\n && setcap cap_net_raw,cap_net_admin+p /build/target/release/sipnab",
        "",
    );
    assert_ne!(text, GOOD, "the synthetic replacement did not apply");
    let p = file_caps_problems(&text, "cap_net_raw,cap_net_admin");
    assert!(
        p.iter().any(|m| m.contains("no stage runs setcap")),
        "{p:?}"
    );
    Ok(())
}

/// GIVEN a chown of the copied binary, a missing libcap2-bin and a root USER
/// WHEN the rule reads each
/// THEN each is refused.
#[test]
fn what_clears_or_wastes_the_file_caps_is_refused() -> Result<(), TestError> {
    let names = "cap_net_raw,cap_net_admin";
    let chown = format!("{GOOD}RUN chown sipnab /usr/local/bin/sipnab\n");
    assert!(
        file_caps_problems(&chown, names)
            .iter()
            .any(|m| m.contains("chown")),
        "a chown after the COPY was accepted"
    );
    let no_libcap = GOOD.replace(" libcap2-bin", "");
    assert!(
        file_caps_problems(&no_libcap, names)
            .iter()
            .any(|m| m.contains("libcap2-bin")),
        "setcap without libcap2-bin was accepted"
    );
    let root = GOOD.replace("USER sipnab", "USER root");
    assert!(
        file_caps_problems(&root, names)
            .iter()
            .any(|m| m.contains("USER")),
        "a root USER was accepted"
    );
    let wrong_names = file_caps_problems(GOOD, "cap_net_raw");
    assert!(
        !wrong_names.is_empty(),
        "caps that differ from what sipnab raises were accepted"
    );
    Ok(())
}

// ── Workflow reader ──────────────────────────────────────────────────────────

/// The text of job `name` in a workflow: from its header at indent 2 to the
/// next key at indent 2 or less.
fn job<'a>(wf: &'a str, name: &str) -> Option<&'a str> {
    let header = format!("\n  {name}:\n");
    let start = wf.find(&header)? + 1;
    let body = start + header.len() - 1;
    let mut end = wf.len();
    let mut off = body;
    for l in wf[body..].split_inclusive('\n') {
        let t = l.trim_start();
        if !t.trim().is_empty() && !t.starts_with('#') && l.len() - t.len() <= 2 {
            end = off;
            break;
        }
        off += l.len();
    }
    Some(&wf[start..end])
}

/// The steps under every `steps:` in `text`, each from its `- ` line to the
/// next one or to the first line indented less than the step.
fn steps(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut indent: Option<usize> = None;
    let mut open = false;
    for line in text.lines() {
        let t = line.trim_start();
        let ind = line.len() - t.len();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t == "steps:" {
            indent = None;
            open = false;
            continue;
        }
        if t.starts_with("- ") && indent.is_none_or(|i| i == ind) {
            indent = Some(ind);
            open = true;
            out.push(String::new());
        } else if indent.is_some_and(|i| ind <= i) {
            open = false;
        }
        if open && let Some(s) = out.last_mut() {
            s.push_str(line);
            s.push('\n');
        }
    }
    out
}

/// The step whose `- name:` is `name`.
fn step(job: &str, name: &str) -> Option<String> {
    let want = format!("- name: {name}");
    steps(job)
        .into_iter()
        .find(|s| s.lines().next().is_some_and(|l| l.trim() == want))
}

/// The value of `key:` in a step (first match, quotes trimmed).
fn input(step: &str, key: &str) -> Option<String> {
    step.lines().find_map(|l| {
        let t = l.trim_start().trim_start_matches("- ");
        let v = t.strip_prefix(key)?.strip_prefix(':')?;
        Some(v.trim().trim_matches(['\'', '"']).to_string())
    })
}

/// The lines of a block scalar `key: |` inside `text`, comments dropped.
fn block(text: &str, key: &str) -> Option<Vec<String>> {
    let mut lines = text.lines();
    let head = lines.by_ref().find(|l| {
        let t = l.trim_start();
        t == format!("{key}: |")
    })?;
    let head_indent = head.len() - head.trim_start().len();
    let mut out = Vec::new();
    for l in lines {
        let t = l.trim_start();
        if t.is_empty() {
            continue;
        }
        if l.len() - t.len() <= head_indent {
            break;
        }
        if !t.starts_with('#') {
            out.push(t.to_string());
        }
    }
    Some(out)
}

// ── OPS-2: what :latest follows ──────────────────────────────────────────────

/// The release-tag condition `:latest` is enabled by: a `v*` tag that is not
/// a pre-release (`v0.1.0-alpha` carries a `-`).
const RELEASE_ONLY: &str =
    "${{ startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-') }}";

/// The comma-separated fields of one metadata-action tag rule, with a comma
/// inside a `${{ }}` expression left in its field.
fn rule_fields(rule: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut from) = (0usize, 0usize);
    let b = rule.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if rule[i..].starts_with("${{") {
            depth += 1;
            i += 3;
            continue;
        }
        if depth > 0 && rule[i..].starts_with("}}") {
            depth -= 1;
            i += 2;
            continue;
        }
        if depth == 0 && b[i] == b',' {
            out.push(&rule[from..i]);
            from = i + 1;
        }
        i += 1;
    }
    out.push(&rule[from..]);
    out
}

/// What is wrong with the tag rules a workflow gives docker/metadata-action,
/// as far as `:latest` and the tag that follows `main` go.
fn tag_problems(wf: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(rules) = block(wf, "IMAGE_TAGS") else {
        return vec!["the workflow `env:` has no `IMAGE_TAGS: |` block".into()];
    };
    let mut edge = false;
    for rule in &rules {
        let fields: Vec<(&str, &str)> = rule_fields(rule)
            .into_iter()
            .filter_map(|f| f.split_once('='))
            .collect();
        let get = |k: &str| fields.iter().find(|(a, _)| *a == k).map(|(_, v)| *v);
        if get("type") == Some("edge") && get("branch") == Some("main") {
            edge = true;
        }
        if get("value") == Some("latest") {
            match get("enable") {
                Some(e) if e == RELEASE_ONLY => {}
                other => problems.push(format!(
                    "`{rule}` enables :latest on {other:?}, not only on a release \
                     tag ({RELEASE_ONLY})"
                )),
            }
        }
        if get("type") == Some("edge") && get("value") == Some("latest") {
            problems.push(format!("`{rule}` makes the main-following tag :latest"));
        }
    }
    if !rules.iter().any(|r| r.contains("value=latest")) {
        problems.push("no rule tags :latest at all".into());
    }
    if !edge {
        problems.push("no `type=edge,branch=main` rule: nothing follows main".into());
    }
    // Every metadata step must read the shared rules and switch the action's
    // own `latest=auto` off, so the rule above is the only one.
    let metas: Vec<String> = steps(wf)
        .into_iter()
        .filter(|s| s.contains("docker/metadata-action@"))
        .collect();
    if metas.is_empty() {
        problems.push("no docker/metadata-action step".into());
    }
    for s in &metas {
        if input(s, "tags").as_deref() != Some("${{ env.IMAGE_TAGS }}") {
            problems.push("a metadata step does not read `${{ env.IMAGE_TAGS }}`".into());
        }
        if input(s, "flavor").as_deref() != Some("latest=false") {
            problems.push(
                "a metadata step leaves `flavor: latest` on auto, a second rule for :latest".into(),
            );
        }
    }
    problems
}

/// GIVEN docker.yml
/// WHEN its tag rules are read
/// THEN `:latest` moves only on a release tag and `:edge` follows main.
#[test]
fn latest_moves_only_on_a_release_tag() -> Result<(), TestError> {
    let p = tag_problems(&read(".github/workflows/docker.yml")?);
    assert!(
        p.is_empty(),
        ":latest must follow releases, not main (OPS-2):\n  {}",
        p.join("\n  ")
    );
    Ok(())
}

/// The synthetic workflow the refusals below vary.
const GOOD_TAGS: &str = "env:\n  IMAGE_TAGS: |\n    type=semver,pattern={{version}}\n    type=edge,branch=main\n    type=raw,value=latest,enable=${{ startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-') }}\njobs:\n  docker:\n    steps:\n      - name: Docker meta\n        uses: docker/metadata-action@0 # v6\n        with:\n          flavor: latest=false\n          tags: ${{ env.IMAGE_TAGS }}\n";

#[test]
fn the_tag_rule_accepts_the_synthetic_good_workflow() {
    assert_eq!(
        tag_problems(GOOD_TAGS),
        Vec::<String>::new(),
        "the synthetic good workflow has no problem"
    );
}

/// GIVEN the rule this defect was found in
/// WHEN it is read
/// THEN it is refused.
#[test]
fn latest_on_the_default_branch_is_refused() -> Result<(), TestError> {
    let text = GOOD_TAGS.replace(
        "enable=${{ startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-') }}",
        "enable={{is_default_branch}}",
    );
    assert_ne!(text, GOOD_TAGS, "the synthetic replacement did not apply");
    let p = tag_problems(&text);
    assert!(p.iter().any(|m| m.contains("is_default_branch")), "{p:?}");
    Ok(())
}

/// GIVEN an unconditional latest, a pre-release-blind condition, an auto
/// flavor, and no main-following tag
/// WHEN each is read
/// THEN each is refused.
#[test]
fn every_other_way_latest_could_follow_main_is_refused() -> Result<(), TestError> {
    let unconditional = GOOD_TAGS.replace(
        ",enable=${{ startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-') }}",
        "",
    );
    assert!(
        !tag_problems(&unconditional).is_empty(),
        "unconditional accepted"
    );
    let prerelease = GOOD_TAGS.replace(" && !contains(github.ref_name, '-')", "");
    assert!(
        !tag_problems(&prerelease).is_empty(),
        "a condition that also matches v0.1.0-alpha was accepted"
    );
    let auto = GOOD_TAGS.replace("          flavor: latest=false\n", "");
    assert!(
        tag_problems(&auto).iter().any(|m| m.contains("auto")),
        "an auto flavor was accepted"
    );
    let no_edge = GOOD_TAGS.replace("    type=edge,branch=main\n", "");
    assert!(
        tag_problems(&no_edge)
            .iter()
            .any(|m| m.contains("follows main")),
        "no main-following tag was accepted"
    );
    Ok(())
}

// ── OPS-3: linux/arm64 ───────────────────────────────────────────────────────

/// The platforms the build legs' matrix lists, with each leg's runner.
fn matrix_legs(job: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut platform: Option<String> = None;
    for line in job.lines() {
        let t = line.trim_start().trim_start_matches("- ");
        if let Some(p) = t.strip_prefix("platform:") {
            platform = Some(p.trim().to_string());
        } else if let Some(r) = t.strip_prefix("os:")
            && let Some(p) = platform.take()
        {
            out.push((p, r.trim().to_string()));
        }
    }
    out
}

/// What is wrong with how a workflow publishes for more than one platform.
fn multi_arch_problems(wf: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(legs_job) = job(wf, "docker") else {
        return vec!["no `docker` job".into()];
    };
    let legs = matrix_legs(legs_job);
    let platforms: BTreeSet<&str> = legs.iter().map(|(p, _)| p.as_str()).collect();
    for want in ["linux/amd64", "linux/arm64"] {
        if !platforms.contains(want) {
            problems.push(format!("the build matrix has no {want} leg: {legs:?}"));
        }
    }
    for (p, runner) in &legs {
        let arm_runner = runner.ends_with("-arm");
        if p.ends_with("arm64") != arm_runner {
            problems.push(format!(
                "{p} builds on `{runner}`, a runner of another architecture, so \
                 it compiles under emulation"
            ));
        }
    }
    if input(legs_job, "runs-on").as_deref() != Some("${{ matrix.os }}") {
        problems.push("the build job does not run on `${{ matrix.os }}`".into());
    }
    if wf
        .lines()
        .any(|l| !l.trim_start().starts_with('#') && l.contains("setup-qemu-action"))
    {
        problems.push("the workflow sets up QEMU: a leg would compile under emulation".into());
    }
    for s in steps(legs_job)
        .iter()
        .filter(|s| s.contains("docker/build-push-action@"))
    {
        if let Some(p) = input(s, "platforms")
            && p != "${{ matrix.platform }}"
        {
            problems.push(format!(
                "a build step builds `{p}`, not its own leg's platform"
            ));
        }
    }
    match step(legs_job, "Build and push") {
        None => problems.push("the build job has no `Build and push` step".into()),
        Some(push) => {
            let outputs = input(&push, "outputs").unwrap_or_default();
            if !outputs.contains("push-by-digest=true") || !outputs.contains("push=true") {
                problems.push(format!(
                    "a leg pushes `{outputs}`, not by digest; a leg that pushes tags \
                     moves them to a single-platform image"
                ));
            }
            if input(&push, "platforms").as_deref() != Some("${{ matrix.platform }}") {
                problems.push("the push step does not name its leg's platform".into());
            }
            if push.contains("steps.meta.outputs.tags") {
                problems.push("a leg pushes the release tags itself".into());
            }
        }
    }
    let Some(manifest) = job(wf, "manifest") else {
        problems.push("no `manifest` job joins the legs".into());
        return problems;
    };
    if input(manifest, "needs").as_deref() != Some("docker") {
        problems.push("the manifest job does not wait for the build legs".into());
    }
    if !manifest.contains("docker buildx imagetools create") {
        problems.push("the manifest job does not create a manifest list".into());
    }
    let Some(check) = step(manifest, "Check the manifest list holds every platform") else {
        problems.push("the manifest job does not check the platforms it published".into());
        return problems;
    };
    let listed = input(&check, "PLATFORMS").unwrap_or_default();
    let listed: BTreeSet<&str> = listed.split_whitespace().collect();
    if listed != platforms {
        problems.push(format!(
            "the manifest check expects {listed:?} and the matrix builds {platforms:?}"
        ));
    }
    match step(manifest, "Attest image provenance") {
        Some(a)
            if input(&a, "subject-digest").as_deref()
                == Some("${{ steps.manifest.outputs.digest }}") => {}
        _ => problems.push(
            "the attestation is not made in the manifest job for the manifest list's \
             digest, so `gh attestation verify oci://...:<tag>` finds none"
                .into(),
        ),
    }
    problems
}

/// GIVEN docker.yml
/// WHEN its build legs and manifest job are read
/// THEN amd64 and arm64 are each built natively, pushed by digest, joined into
/// one checked manifest list, and attested there.
#[test]
fn the_image_is_published_for_amd64_and_arm64() -> Result<(), TestError> {
    let p = multi_arch_problems(&read(".github/workflows/docker.yml")?);
    assert!(
        p.is_empty(),
        "the image is not published as linux/amd64 + linux/arm64 (OPS-3):\n  {}",
        p.join("\n  ")
    );
    Ok(())
}

/// GIVEN the publishing workflow this defect was found in: one leg on
/// ubuntu-latest, no matrix and no manifest job
/// WHEN it is read
/// THEN it is refused for the missing arm64 leg.
#[test]
fn an_amd64_only_workflow_is_refused() {
    let wf = "jobs:\n  docker:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Build and push\n        uses: docker/build-push-action@0 # v7\n        with:\n          push: true\n";
    let p = multi_arch_problems(wf);
    assert!(p.iter().any(|m| m.contains("linux/arm64")), "{p:?}");
    assert!(p.iter().any(|m| m.contains("manifest")), "{p:?}");
}

/// GIVEN an arm64 leg on an amd64 runner, and a QEMU setup
/// WHEN each is read
/// THEN each is refused as an emulated compile.
#[test]
fn an_emulated_arm64_leg_is_refused() -> Result<(), TestError> {
    let wf = read(".github/workflows/docker.yml")?;
    let swapped = wf.replace("os: ubuntu-24.04-arm", "os: ubuntu-latest");
    assert_ne!(swapped, wf, "docker.yml has no `os: ubuntu-24.04-arm` leg");
    assert!(
        multi_arch_problems(&swapped)
            .iter()
            .any(|m| m.contains("emulation")),
        "an arm64 leg on an amd64 runner was accepted"
    );
    let qemu = wf.replace(
        "      - name: Set up Docker Buildx\n",
        "      - uses: docker/setup-qemu-action@0 # v3\n      - name: Set up Docker Buildx\n",
    );
    assert_ne!(qemu, wf, "the QEMU insertion did not apply");
    assert!(
        multi_arch_problems(&qemu)
            .iter()
            .any(|m| m.contains("QEMU")),
        "a QEMU setup was accepted"
    );
    Ok(())
}

/// GIVEN a leg that pushes tags, and a manifest check that misses a platform
/// WHEN each is read
/// THEN each is refused.
#[test]
fn a_leg_pushing_tags_or_an_unchecked_platform_is_refused() -> Result<(), TestError> {
    let wf = read(".github/workflows/docker.yml")?;
    let check = wf
        .lines()
        .find(|l| l.trim_start().starts_with("PLATFORMS:"))
        .ok_or("docker.yml has no PLATFORMS line")?;
    let short = wf.replace(check, &check.replace(" linux/arm64", ""));
    assert_ne!(short, wf, "the PLATFORMS line has no linux/arm64");
    assert!(
        multi_arch_problems(&short)
            .iter()
            .any(|m| m.contains("manifest check expects")),
        "a manifest check that skips arm64 was accepted"
    );
    let outputs = wf
        .lines()
        .find(|l| l.trim_start().starts_with("outputs:") && l.contains("push-by-digest"))
        .ok_or("docker.yml has no push-by-digest outputs line")?;
    let tagged = wf.replace(outputs, &outputs.replace("push-by-digest=true,", ""));
    assert!(
        multi_arch_problems(&tagged)
            .iter()
            .any(|m| m.contains("not by digest")),
        "a leg that pushes by name was accepted"
    );
    Ok(())
}

/// GIVEN the workflow's two build legs
/// WHEN their scan uploads and build caches are read
/// THEN each leg has its own SARIF category and its own cache scope, so one
/// leg's results and layers do not replace the other's.
#[test]
fn each_leg_keeps_its_own_scan_results_and_cache() -> Result<(), TestError> {
    let wf = read(".github/workflows/docker.yml")?;
    let legs = job(&wf, "docker").ok_or("no docker job")?;
    let upload = step(legs, "Upload image scan results").ok_or("no upload step")?;
    let category = input(&upload, "category").unwrap_or_default();
    assert!(
        category.contains("matrix."),
        "the SARIF category `{category}` is the same for both legs, so the \
         second upload replaces the first leg's findings"
    );
    let builds: Vec<String> = steps(legs)
        .into_iter()
        .filter(|s| s.contains("docker/build-push-action@"))
        .collect();
    assert_eq!(
        builds.len(),
        2,
        "expected the smoke build and the push build"
    );
    for b in &builds {
        for key in ["cache-from", "cache-to"] {
            let v = input(b, key).unwrap_or_default();
            assert!(
                v.contains("scope=") && v.contains("matrix.arch"),
                "`{key}: {v}` is shared by both legs; each leg's mode=max write \
                 replaces the other's cache"
            );
        }
    }
    Ok(())
}

/// GIVEN a synthetic job
/// WHEN the workflow readers run
/// THEN they find the job, its steps, a step's inputs and a block.
#[test]
fn the_workflow_readers_find_jobs_steps_inputs_and_blocks() -> Result<(), TestError> {
    let wf = "env:\n  B: |\n    one\n    # skipped\n    two\njobs:\n  a:\n    runs-on: x\n    steps:\n      - name: First\n        with:\n          k: 'v'\n      - name: Second\n        run: |\n          - not a step\n  b:\n    runs-on: y\n";
    let a = job(wf, "a").ok_or("no job a")?;
    assert!(a.contains("runs-on: x") && !a.contains("runs-on: y"), "{a}");
    assert_eq!(steps(a).len(), 2, "{:?}", steps(a));
    let first = step(a, "First").ok_or("no step First")?;
    assert_eq!(
        input(&first, "k").as_deref(),
        Some("v"),
        "a step input is read by its key"
    );
    assert_eq!(
        block(wf, "B"),
        Some(vec!["one".to_string(), "two".to_string()]),
        "a block scalar is read line by line"
    );
    assert_eq!(
        rule_fields("type=raw,enable=${{ f(a, 'b') }},value=x"),
        vec!["type=raw", "enable=${{ f(a, 'b') }}", "value=x"],
        "a comma inside an expression does not split a field"
    );
    let legs = "    strategy:\n      matrix:\n        include:\n          - platform: linux/amd64\n            os: ubuntu-latest\n          - platform: linux/arm64\n            os: ubuntu-24.04-arm\n";
    assert_eq!(
        matrix_legs(legs),
        vec![
            ("linux/amd64".to_string(), "ubuntu-latest".to_string()),
            ("linux/arm64".to_string(), "ubuntu-24.04-arm".to_string())
        ],
        "one leg per matrix entry, platform then runner"
    );
    Ok(())
}

/// GIVEN the smoke test each build leg runs on its own image
/// WHEN it is read
/// THEN it opens a live capture as the image's user with `--cap-add` alone,
/// starts the image with no capability at all, and checks for the CA bundle at
/// a path sipnab reads, so each fix is exercised on both platforms before
/// anything is pushed.
#[test]
fn the_smoke_test_exercises_the_capture_and_bundle_fixes() -> Result<(), TestError> {
    let wf = read(".github/workflows/docker.yml")?;
    let legs = job(&wf, "docker").ok_or("no docker job")?;
    let smoke = step(legs, "Smoke test the image").ok_or("no smoke test step")?;
    let capture = smoke
        .lines()
        .position(|l| l.contains("--cap-add NET_RAW --cap-add NET_ADMIN"))
        .ok_or("the smoke test never runs the image with --cap-add NET_RAW --cap-add NET_ADMIN")?;
    let run: String = smoke.lines().skip(capture).take(2).collect();
    assert!(
        run.contains(" -d lo") && !run.contains("--user"),
        "the --cap-add run must capture live as the image's own user: {run}"
    );
    assert!(
        smoke.contains("--cap-drop ALL sipnab:smoke --version"),
        "the smoke test does not start the image with no capability, the case \
         an effective file-capability bit breaks"
    );
    let paths = system_ca_bundles(&read("src/tls_files.rs")?)?;
    assert!(
        paths
            .iter()
            .any(|p| smoke.contains(&format!("test sipnab:smoke -s {p}"))),
        "the smoke test checks no CA bundle at a path sipnab reads ({paths:?})"
    );
    Ok(())
}

// ── The raise at startup (OPS-4) ─────────────────────────────────────────────

/// The call that moves the permitted capture capabilities into the effective
/// set, as `src/main.rs` spells it.
const RAISE_CALL: &str = "privilege::raise_capture_capabilities()";

/// What is wrong with where `main_rs` raises the capture capabilities; empty
/// when nothing is.
///
/// The image's binary carries the capabilities permitted only, so without
/// the call its user holds them and cannot use them. The wire cannot be
/// driven from a test: it needs a binary with file capabilities, which only
/// root can set, so the image's smoke test in `docker.yml` runs the capture
/// and this rule holds the source. The call must be in `main`, once, and
/// before the command line is parsed: capability sets belong to a thread,
/// each new thread copies its creator's, and nothing before the parse starts
/// one.
fn startup_raise_problems(main_rs: &str) -> Vec<String> {
    let Some(body) = main_rs.split("\nfn main() {").nth(1) else {
        return vec!["src/main.rs has no `fn main() {`".to_string()];
    };
    let body = body.split("\n}\n").next().unwrap_or(body);
    let code: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut problems = Vec::new();
    match code.matches(RAISE_CALL).count() {
        0 => problems.push(format!("main never calls {RAISE_CALL}")),
        1 => {}
        n => problems.push(format!("main calls {RAISE_CALL} {n} times")),
    }
    let raise = code.find(RAISE_CALL);
    let parse = code.find("Cli::parse_args()");
    match (raise, parse) {
        (Some(raise), Some(parse)) if raise > parse => problems.push(format!(
            "main calls {RAISE_CALL} after it parses the command line"
        )),
        (_, None) => problems.push("main no longer calls Cli::parse_args()".to_string()),
        _ => {}
    }
    problems
}

/// SUCCESS: `src/main.rs` raises the capabilities once, before the parse.
#[test]
fn main_raises_the_capture_capabilities_before_it_parses() -> Result<(), TestError> {
    let problems = startup_raise_problems(&read("src/main.rs")?);
    assert!(problems.is_empty(), "{problems:#?}");
    Ok(())
}

/// A `main` in the shape the rule reads, with `steps` as its body.
fn synthetic_main(steps: &str) -> String {
    format!("use x;\n\nfn main() {{\n{steps}}}\n\nfn other() {{\n    let _ = 1;\n}}\n")
}

/// FAILURE: a `main` that never raises, or only names the call in a comment
/// or in another function, is refused.
#[test]
fn a_main_that_never_raises_is_refused() {
    let never = synthetic_main("    let cli = Cli::parse_args();\n");
    assert_eq!(
        startup_raise_problems(&never),
        vec![format!("main never calls {RAISE_CALL}")],
        "no call at all"
    );
    let commented = synthetic_main(&format!(
        "    // let raised = sipnab::{RAISE_CALL};\n    let cli = Cli::parse_args();\n"
    ));
    assert_eq!(
        startup_raise_problems(&commented),
        vec![format!("main never calls {RAISE_CALL}")],
        "a commented call is no call"
    );
    let elsewhere = format!(
        "{}fn later() {{\n    let _ = sipnab::{RAISE_CALL};\n}}\n",
        synthetic_main("    let cli = Cli::parse_args();\n")
    );
    assert_eq!(
        startup_raise_problems(&elsewhere),
        vec![format!("main never calls {RAISE_CALL}")],
        "a call in another function is not at startup"
    );
}

/// FAILURE: a raise after the parse, where logging and its threads may have
/// started, is refused; so is a second raise.
#[test]
fn a_raise_after_the_parse_or_a_second_raise_is_refused() {
    let late = synthetic_main(&format!(
        "    let cli = Cli::parse_args();\n    let raised = sipnab::{RAISE_CALL};\n"
    ));
    assert_eq!(
        startup_raise_problems(&late),
        vec![format!(
            "main calls {RAISE_CALL} after it parses the command line"
        )],
        "the raise must come first"
    );
    let twice = synthetic_main(&format!(
        "    let a = sipnab::{RAISE_CALL};\n    let cli = Cli::parse_args();\n    let b = sipnab::{RAISE_CALL};\n"
    ));
    assert_eq!(
        startup_raise_problems(&twice),
        vec![format!("main calls {RAISE_CALL} 2 times")],
        "one raise, before the parse"
    );
}

/// EDGE: the rule accepts the synthetic good `main`, and says so when a file
/// has no `main` or its `main` no longer parses a command line.
#[test]
fn the_startup_rule_reads_the_shapes_it_is_given() {
    let good = synthetic_main(&format!(
        "    let raised = sipnab::{RAISE_CALL};\n    let cli = Cli::parse_args();\n"
    ));
    assert_eq!(
        startup_raise_problems(&good),
        Vec::<String>::new(),
        "the synthetic good main"
    );
    assert_eq!(
        startup_raise_problems("fn other() {}\n"),
        vec!["src/main.rs has no `fn main() {`".to_string()],
        "a file with no main"
    );
    let no_parse = synthetic_main(&format!("    let raised = sipnab::{RAISE_CALL};\n"));
    assert_eq!(
        startup_raise_problems(&no_parse),
        vec!["main no longer calls Cli::parse_args()".to_string()],
        "a main the rule can no longer place the raise in"
    );
}
