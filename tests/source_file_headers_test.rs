// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! Every source file names its license and its copyright holder.
//!
//! OpenSSF Gold asks for both, per file: `license_per_file` ("a license
//! statement in each source file ... SPDX-License-Identifier") and
//! `copyright_per_file` ("a copyright statement in each source file,
//! identifying the copyright holder"). A file copied out of this repository on
//! its own still says whose it is and on what terms.
//!
//! What counts as a source file, the two statements, and the files that are
//! deliberately not labeled all live in `.config/source-headers.txt`. This
//! gate and its fixer, `scripts/add-source-headers.py --apply`, both read that
//! file, so they cannot disagree about the scope.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The error a test returns: any error, boxed, so `?` works on I/O, parse and
/// UTF-8 errors alike.
type TestError = Box<dyn std::error::Error>;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

const CONFIG: &str = ".config/source-headers.txt";
const FIXER: &str = "scripts/add-source-headers.py";

/// What a git hook exports into its children; see the fixer test.
const HOOK_GIT_ENV: [&str; 5] = [
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_OBJECT_DIRECTORY",
];

/// How a file in scope is matched, and the comment syntax it is written in.
#[derive(Debug, Clone)]
enum Matcher {
    Ext(String),
    Name(String),
    Prefix(String),
    Shebang,
}

#[derive(Debug, Clone)]
struct Rule {
    matcher: Matcher,
    open: String,
}

#[derive(Debug)]
struct Config {
    license: String,
    copyright: String,
    window: usize,
    rules: Vec<Rule>,
    excludes: Vec<String>,
}

fn parse_config(text: &str) -> Result<Config, TestError> {
    let mut license = None;
    let mut copyright = None;
    let mut window = None;
    let mut rules = Vec::new();
    let mut excludes = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| format!("{CONFIG}:{}: `{line}` has no value", n + 1))?;
        let rest = rest.trim();
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let field = |i: usize| -> Result<String, TestError> {
            Ok(fields
                .get(i)
                .ok_or_else(|| format!("{CONFIG}:{}: `{line}` lacks field {}", n + 1, i + 1))?
                .to_string())
        };
        match key {
            "license" => license = Some(rest.to_string()),
            "copyright" => copyright = Some(rest.to_string()),
            "window" => window = Some(rest.parse::<usize>()?),
            "ext" => rules.push(Rule {
                matcher: Matcher::Ext(field(0)?),
                open: field(1)?,
            }),
            "name" => rules.push(Rule {
                matcher: Matcher::Name(field(0)?),
                open: field(1)?,
            }),
            "prefix" => rules.push(Rule {
                matcher: Matcher::Prefix(field(0)?),
                open: field(1)?,
            }),
            "shebang" => rules.push(Rule {
                matcher: Matcher::Shebang,
                open: field(0)?,
            }),
            "exclude" => excludes.push(rest.to_string()),
            other => return Err(format!("{CONFIG}:{}: unknown directive `{other}`", n + 1).into()),
        }
    }
    Ok(Config {
        license: license.ok_or("config names no license")?,
        copyright: copyright.ok_or("config names no copyright holder")?,
        window: window.ok_or("config names no window")?,
        rules,
        excludes,
    })
}

fn load_config() -> Result<Config, TestError> {
    parse_config(&std::fs::read_to_string(repo().join(CONFIG))?)
}

/// The rule a tracked path falls under, if it is a source file at all.
/// `first_line` is only consulted for the shebang rule, after every
/// name-based rule has declined the path.
fn rule_for<'a>(config: &'a Config, path: &str, first_line: &str) -> Option<&'a Rule> {
    let base = path.rsplit('/').next().unwrap_or(path);
    let by_name = config.rules.iter().find(|r| match &r.matcher {
        Matcher::Ext(ext) => base.ends_with(ext.as_str()),
        Matcher::Name(name) => base == name,
        Matcher::Prefix(prefix) => base.starts_with(prefix.as_str()),
        Matcher::Shebang => false,
    });
    by_name.or_else(|| {
        if first_line.starts_with("#!") {
            config
                .rules
                .iter()
                .find(|r| matches!(r.matcher, Matcher::Shebang))
        } else {
            None
        }
    })
}

/// What is wrong with a file's header, or `None` when it has both statements
/// inside a comment within the first `window` lines.
fn header_problems(config: &Config, rule: &Rule, text: &str) -> Option<String> {
    let license = format!("SPDX-License-Identifier: {}", config.license);
    let copyright = format!("SPDX-FileCopyrightText: {}", config.copyright);
    let head: Vec<&str> = text.lines().take(config.window).collect();
    let is_comment = |l: &str| l.trim_start().starts_with(rule.open.as_str());
    // The statement must be the WHOLE rest of the comment, so a differing
    // expression that merely starts the same way (`MIT OR Apache-2.0 WITH x`)
    // does not pass as the project's.
    let states = |l: &str, statement: &str| {
        let body = l.trim_start()[rule.open.len()..].trim();
        let body = body.strip_suffix("#}").unwrap_or(body).trim();
        body == statement
    };
    let mut problems = Vec::new();
    if !head.iter().any(|l| is_comment(l) && states(l, &license)) {
        problems.push(format!("no `{} {license}`", rule.open));
    }
    if !head.iter().any(|l| is_comment(l) && states(l, &copyright)) {
        problems.push(format!("no `{} {copyright}`", rule.open));
    }
    for l in &head {
        if l.contains("SPDX-License-Identifier:") && !(is_comment(l) && states(l, &license)) {
            problems.push(format!("a different license statement: `{}`", l.trim()));
        }
    }
    if problems.is_empty() {
        None
    } else {
        Some(problems.join("; "))
    }
}

fn tracked_files() -> Result<Vec<String>, TestError> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo())
        .output()?;
    assert!(out.status.success(), "git ls-files failed");
    Ok(String::from_utf8(out.stdout)?
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect())
}

fn first_line(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_default();
    let end = bytes
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Every tracked source file, minus the named exclusions, with its rule.
fn in_scope(config: &Config) -> Result<Vec<(String, Rule)>, TestError> {
    Ok(tracked_files()?
        .into_iter()
        .filter(|p| !config.excludes.contains(p))
        .filter_map(|p| {
            let full = repo().join(&p);
            // A tracked path deleted in the working tree is not a file to read.
            if !full.is_file() {
                return None;
            }
            rule_for(config, &p, &first_line(&full)).map(|r| (p, r.clone()))
        })
        .collect())
}

/// The gate. The sanity floor matters as much as the loop: a scope that
/// quietly matched nothing (a broken config, a `git` that listed nothing)
/// would pass every file it never looked at.
#[test]
fn every_source_file_names_its_license_and_copyright_holder() -> Result<(), TestError> {
    let config = load_config()?;
    let files = in_scope(&config)?;
    assert!(
        files.len() >= 900,
        "only {} source files in scope; the tree holds over 900. Is \
         {CONFIG} or `git ls-files` broken?",
        files.len()
    );
    let mut failures = Vec::new();
    for (path, rule) in &files {
        let text = std::fs::read(repo().join(path))?;
        let text = String::from_utf8_lossy(&text);
        if let Some(problem) = header_problems(&config, rule, &text) {
            failures.push(format!("  {path}: {problem}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} source files lack the license or copyright statement in their \
         first {} lines (OpenSSF Gold license_per_file / copyright_per_file):\n{}\n\n\
         Fix: python3 {FIXER} --apply\n\
         If a file is not ours to label (vendored, generated), add an \
         `exclude` with the reason to {CONFIG}.",
        failures.len(),
        files.len(),
        config.window,
        failures.join("\n")
    );
    Ok(())
}

/// The per-file statement and the crate's declared license are one fact. If
/// the project relicenses, the gate must not keep demanding the old terms.
#[test]
fn the_config_license_is_the_crate_license() -> Result<(), TestError> {
    let config = load_config()?;
    let manifest = std::fs::read_to_string(repo().join("Cargo.toml"))?;
    let declared = manifest
        .lines()
        .find_map(|l| l.strip_prefix("license = "))
        .ok_or("Cargo.toml declares no license")?
        .trim()
        .trim_matches('"');
    assert_eq!(
        config.license, declared,
        "{CONFIG} and Cargo.toml disagree about the project license"
    );
    Ok(())
}

/// An exclusion must name a tracked file the scope would otherwise demand a
/// header of. A stale one (the file moved, or left the scope) is a hole with
/// nothing in it, waiting for an unrelated file to fall through.
#[test]
fn every_exclusion_names_a_tracked_in_scope_file() -> Result<(), TestError> {
    let config = load_config()?;
    let tracked = tracked_files()?;
    let mut stale = Vec::new();
    for path in &config.excludes {
        let full = repo().join(path);
        if !tracked.contains(path) || rule_for(&config, path, &first_line(&full)).is_none() {
            stale.push(path.as_str());
        }
    }
    assert!(stale.is_empty(), "stale exclusions in {CONFIG}: {stale:?}");
    Ok(())
}

fn rust_rule() -> Rule {
    Rule {
        matcher: Matcher::Ext(".rs".into()),
        open: "//".into(),
    }
}

fn fixture_config() -> Result<Config, TestError> {
    parse_config(
        "license MIT OR Apache-2.0\ncopyright The sipnab contributors\nwindow 3\n\
         ext .rs //\next .html {# #}\nshebang #\nexclude vendor.min.js\n",
    )
}

/// The checker, driven directly: each way a header can be wrong is refused,
/// and the right header is accepted. Without this, a checker that accepted
/// everything would pass the gate above over any tree.
#[test]
fn the_checker_refuses_each_wrong_header_and_accepts_the_right_one() -> Result<(), TestError> {
    let c = fixture_config()?;
    let r = rust_rule();
    let good = "// SPDX-License-Identifier: MIT OR Apache-2.0\n\
                // SPDX-FileCopyrightText: The sipnab contributors\nfn main() {}\n";
    assert_eq!(header_problems(&c, &r, good), None);

    let no_copyright = "// SPDX-License-Identifier: MIT OR Apache-2.0\nfn main() {}\n";
    assert!(
        header_problems(&c, &r, no_copyright)
            .ok_or("no_copyright passed")?
            .contains("SPDX-FileCopyrightText")
    );

    let no_license = "// SPDX-FileCopyrightText: The sipnab contributors\nfn main() {}\n";
    assert!(
        header_problems(&c, &r, no_license)
            .ok_or("no_license passed")?
            .contains("SPDX-License-Identifier")
    );

    let other_license = "// SPDX-License-Identifier: GPL-3.0-or-later\n\
                         // SPDX-FileCopyrightText: The sipnab contributors\n";
    assert!(
        header_problems(&c, &r, other_license)
            .ok_or("other_license passed")?
            .contains("GPL-3.0-or-later")
    );

    let longer_expression = "// SPDX-License-Identifier: MIT OR Apache-2.0 WITH LLVM-exception\n\
                             // SPDX-FileCopyrightText: The sipnab contributors\n";
    assert!(header_problems(&c, &r, longer_expression).is_some());

    // Past the window (3 lines) does not count as "near the beginning".
    let too_late = "\n\n\n// SPDX-License-Identifier: MIT OR Apache-2.0\n\
                    // SPDX-FileCopyrightText: The sipnab contributors\n";
    assert!(header_problems(&c, &r, too_late).is_some());

    // In a string, not a comment.
    let not_a_comment = "let a = \"// SPDX-License-Identifier: MIT OR Apache-2.0\";\n\
                         let b = \"// SPDX-FileCopyrightText: The sipnab contributors\";\n";
    assert!(header_problems(&c, &r, not_a_comment).is_some());

    let html = Rule {
        matcher: Matcher::Ext(".html".into()),
        open: "{#".into(),
    };
    let tera = "{# SPDX-License-Identifier: MIT OR Apache-2.0 #}\n\
                {# SPDX-FileCopyrightText: The sipnab contributors #}\n<p></p>\n";
    assert_eq!(header_problems(&c, &html, tera), None);
    Ok(())
}

/// The scope matcher, driven directly: extension, exclusion and shebang.
#[test]
fn the_scope_matches_by_extension_and_shebang_and_honors_exclusions() -> Result<(), TestError> {
    let c = fixture_config()?;
    assert!(rule_for(&c, "src/lib.rs", "").is_some());
    assert!(rule_for(&c, "docs/x.md", "").is_none());
    assert!(rule_for(&c, ".githooks/pre-commit", "#!/usr/bin/env bash").is_some());
    assert!(rule_for(&c, "fuzz/corpus/x", "INVITE sip:a SIP/2.0").is_none());
    assert_eq!(c.excludes, vec!["vendor.min.js".to_string()]);
    Ok(())
}

/// The fixer's output must satisfy this gate, and running it twice must
/// change nothing the second time. Driven on a scratch tree so it cannot
/// touch the real one; the shebang, the encoding line and the executable bit
/// are the three things a careless insert destroys.
#[test]
fn the_fixer_output_passes_the_gate_and_is_idempotent() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    // Under `git commit` the hook exports these, pointing at the repository
    // being committed to. Inherited, `git init` and `git add` below would act
    // on THAT index instead of the scratch tree, and so would the fixer's own
    // `git ls-files`.
    let scrubbed = |cmd: &mut Command| {
        for var in HOOK_GIT_ENV {
            cmd.env_remove(var);
        }
    };
    let run = |args: &[&str]| -> Result<(), TestError> {
        let mut cmd = Command::new("git");
        scrubbed(&mut cmd);
        let out = cmd.args(args).current_dir(root).output()?;
        assert!(
            out.status.success(),
            "git {args:?} failed in the scratch tree"
        );
        Ok(())
    };
    run(&["init", "-q"])?;
    std::fs::create_dir_all(root.join(".config"))?;
    std::fs::copy(repo().join(CONFIG), root.join(CONFIG))?;
    let files: &[(&str, &str)] = &[
        ("a.rs", "//! Doc.\nfn main() {}\n"),
        (
            "b.rs",
            "// SPDX-License-Identifier: MIT OR Apache-2.0\n//! Doc.\n",
        ),
        (
            "c.py",
            "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n\"\"\"Doc.\"\"\"\n",
        ),
        ("d.sh", "#!/bin/sh\necho hi\n"),
        ("e.go", "// Command e does a thing.\npackage main\n"),
        ("f.html", "<!DOCTYPE html>\n<html></html>\n"),
        (
            "g.html",
            "{% extends \"base.html\" %}\n{% block body %}{% endblock %}\n",
        ),
        (
            "h.html",
            "{% extends \"base.html\" %}\n{% import \"macros.html\" as macros %}\n\n{% block body %}{% endblock %}\n",
        ),
        ("hook", "#!/bin/bash\ntrue\n"),
        ("website/static/js/mermaid.min.js", "vendored();\n"),
        ("notes.md", "# Notes\n"),
    ];
    for (path, body) in files {
        let full = root.join(path);
        std::fs::create_dir_all(full.parent().ok_or("a scratch path has a parent")?)?;
        std::fs::write(&full, body)?;
    }
    std::fs::set_permissions(root.join("d.sh"), std::fs::Permissions::from_mode(0o755))?;
    run(&["add", "."])?;

    let fix = || -> Result<(), TestError> {
        let mut cmd = Command::new("python3");
        scrubbed(&mut cmd);
        let out = cmd
            .arg(repo().join(FIXER))
            .arg("--apply")
            .current_dir(root)
            .output()?;
        assert!(
            out.status.success(),
            "fixer failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    };
    fix()?;
    let after_first = files
        .iter()
        .map(|(p, _)| std::fs::read(root.join(p)))
        .collect::<Result<Vec<Vec<u8>>, _>>()?;
    fix()?;
    for ((path, _), first) in files.iter().zip(&after_first) {
        assert_eq!(
            &std::fs::read(root.join(path))?,
            first,
            "{path}: a second --apply changed it"
        );
    }

    let config = load_config()?;
    for (path, body) in files {
        let text = std::fs::read_to_string(root.join(path))?;
        let first = text.lines().next().unwrap_or("").to_string();
        match rule_for(&config, path, &first) {
            Some(rule) if !config.excludes.contains(&path.to_string()) => {
                assert_eq!(
                    header_problems(&config, rule, &text),
                    None,
                    "{path} after the fixer:\n{text}"
                );
            }
            _ => assert_eq!(&text, body, "{path} is out of scope and must be untouched"),
        }
    }

    let py = std::fs::read_to_string(root.join("c.py"))?;
    assert!(
        py.starts_with("#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n"),
        "the shebang and the encoding line (PEP 263: line 1 or 2) must stay on top:\n{py}"
    );
    let html = std::fs::read_to_string(root.join("f.html"))?;
    assert!(
        html.starts_with("<!DOCTYPE html>\n"),
        "the doctype must stay first in the rendered page:\n{html}"
    );
    // Tera: `site_journey_test` holds every page template to starting with its
    // `extends`, so the header goes under it.
    let tera = std::fs::read_to_string(root.join("g.html"))?;
    assert!(
        tera.starts_with("{% extends \"base.html\" %}\n"),
        "the template's extends must stay first:\n{tera}"
    );
    // Tera reads `{% import %}` only directly after `{% extends %}`, before
    // any other content, a comment included: a header between them fails the
    // site build ("unexpected tag").
    let imports = std::fs::read_to_string(root.join("h.html"))?;
    assert!(
        imports
            .starts_with("{% extends \"base.html\" %}\n{% import \"macros.html\" as macros %}\n"),
        "the template's extends and imports must stay first:\n{imports}"
    );
    let sh = std::fs::read_to_string(root.join("d.sh"))?;
    assert!(
        sh.starts_with("#!/bin/sh\n"),
        "the shebang must stay first:\n{sh}"
    );
    let mode = std::fs::metadata(root.join("d.sh"))?.permissions().mode();
    assert_eq!(mode & 0o111, 0o111, "the fixer dropped the executable bit");

    // Go: a comment directly above `package` is the package's doc comment, so
    // the header must be separated from it by a blank line.
    let go = std::fs::read_to_string(root.join("e.go"))?;
    assert!(
        go.contains("contributors\n\n// Command e"),
        "the Go header ran into the package doc comment:\n{go}"
    );
    // An existing license line gains the copyright line beside it; it is not
    // duplicated.
    let b = std::fs::read_to_string(root.join("b.rs"))?;
    assert_eq!(b.matches("SPDX-License-Identifier").count(), 1, "{b}");
    Ok(())
}
