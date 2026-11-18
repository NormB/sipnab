// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! No test may return early with success unless the shared prerequisite
//! helper made that decision.
//!
//! # The defect
//!
//! 288 early `return Ok(())` / `return;` statements sat in the bodies of tests
//! that were not `#[ignore]`d (counted on main 62578e3ed, 2026-11-18). Most
//! ran when a prerequisite was missing (no passwordless sudo, no Landlock, no
//! `editcap`, no `/dev/full`) and the test then reported `ok` having tested
//! nothing; some printed a notice that libtest and nextest then discarded.
//!
//! # The rule
//!
//! Every early success return in a test body is refused unless one of these
//! holds:
//!
//! 1. the block it returns from was opened on a decision of
//!    `src/test_prereq.rs`: the block's head, or the code from the block's
//!    opening brace to the return, calls `test_prereq::` or a function whose
//!    own body does (a wrapper, found across every scanned file, transitively);
//! 2. a comment `// not a prerequisite: <reason>` on a line from the block's
//!    opening brace to the return says why the return is no skip (a child
//!    role, a case root cannot build, an input that is legitimately absent).
//!
//! A test marked `#[ignore]` is not scanned: libtest reports it as ignored,
//! not as passed. A return inside a closure or a nested `fn` is not the
//! test's return.

#[path = "support/source_scan.rs"]
mod source_scan;
#[path = "../src/test_prereq.rs"]
mod test_prereq;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

/// The marker that says an early return is no prerequisite skip.
const MARKER: &str = "not a prerequisite:";

/// Fewer source files than this means the walk lost a directory.
const MIN_FILES: usize = 900;

/// Fewer tests than this means the test finder broke.
const MIN_TESTS: usize = 15_000;

/// One refused early return.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    /// The file, as given.
    file: String,
    /// The 1-based line of the `return`.
    line: usize,
    /// The test it returns from.
    test: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: test `{}`", self.file, self.line, self.test)
    }
}

/// The functions that decide through the helper, by where they may be
/// called from.
#[derive(Debug, Default)]
struct Wrappers {
    /// Defined in a `tests/support/` module: a wrapper when called by a
    /// qualified path (`corpus_support::root()`).
    support: BTreeSet<String>,
    /// Defined in a file: a wrapper in that file only, by file.
    local: std::collections::BTreeMap<String, BTreeSet<String>>,
}

/// Whether `file` is a shared support module.
fn is_support(file: &str) -> bool {
    file.contains("support/")
}

/// The 1-based line of byte `offset` in `text`.
fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// The offset of the `}` that closes the `{` at `open`, in code.
fn matching(code: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, &b) in code.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// The code before the `{` at `open` that belongs to it: back to the last
/// `;`, `{` or `}` (or an unclosed `(`) outside parentheses.
fn head(code: &str, open: usize) -> &str {
    let b = code.as_bytes();
    let mut parens = 0usize;
    let mut i = open;
    while i > 0 {
        let c = b[i - 1];
        match c {
            b')' => parens += 1,
            b'(' if parens == 0 => break,
            b'(' => parens -= 1,
            b';' | b'{' | b'}' if parens == 0 => break,
            _ => {}
        }
        i -= 1;
    }
    &code[i..open]
}

/// Whether a block with this head is a closure, a nested `fn` or an async
/// block: its returns are not the enclosing test's.
fn is_nested(head: &str) -> bool {
    NESTED
        .as_ref()
        .is_some_and(|re| re.is_match(head.trim_end()))
}

/// A pattern the scanner uses; `None` if it does not compile, which
/// `every_pattern_the_gate_uses_compiles` refuses.
type Pattern = std::sync::LazyLock<Option<regex::Regex>>;

/// A closure, a nested `fn` or an async block, at the end of a block's head.
static NESTED: Pattern = Pattern::new(|| {
    regex::Regex::new(r"(\|[^|]*\|\s*(->[^|{]*)?$)|\bfn\b|\basync(\s+move)?\s*$").ok()
});

/// A call: an identifier followed by `(`, with the `::` before it if any.
static CALL: Pattern =
    Pattern::new(|| regex::Regex::new(r"(::)?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(").ok());

/// A test attribute: `#[test]` or `#[tokio::test(...)]`.
static ATTR: Pattern =
    Pattern::new(|| regex::Regex::new(r"#\[\s*(tokio::)?test\s*(\([^\]]*\))?\s*\]").ok());

/// A function's name after `fn`.
static FN: Pattern = Pattern::new(|| regex::Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)").ok());

/// The names `text` (code) calls, as (unqualified, called by a `path::`).
fn calls(text: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut bare = BTreeSet::new();
    let mut qualified = BTreeSet::new();
    let Some(call) = CALL.as_ref() else {
        return (bare, qualified);
    };
    for c in call.captures_iter(text) {
        let Some(name) = c.get(2) else {
            continue;
        };
        let set = if c.get(1).is_some() {
            &mut qualified
        } else {
            &mut bare
        };
        set.insert(name.as_str().to_owned());
    }
    (bare, qualified)
}

/// Whether `text` (code, in `file`) calls the helper or a wrapper it may
/// reach.
fn decides(file: &str, text: &str, wrappers: &Wrappers) -> bool {
    if text.contains("test_prereq::") {
        return true;
    }
    let (bare, qualified) = calls(text);
    let local = wrappers.local.get(file);
    bare.iter().any(|n| local.is_some_and(|l| l.contains(n)))
        || qualified.iter().any(|n| wrappers.support.contains(n))
}

/// A test function's name and body braces.
struct TestFn {
    /// Its name.
    name: String,
    /// The offset of the body's `{`.
    open: usize,
    /// The offset of the body's `}`.
    close: usize,
    /// Whether it carries `#[ignore]`.
    ignored: bool,
}

/// Every test function in `code`.
fn test_fns(code: &str) -> Vec<TestFn> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    let (Some(attrs), Some(fns)) = (ATTR.as_ref(), FN.as_ref()) else {
        return out;
    };
    for attr in attrs.find_iter(code) {
        let Some(f) = fns.captures(&code[attr.end()..]) else {
            continue;
        };
        let (Some(whole), Some(name)) = (f.get(0), f.get(1)) else {
            continue;
        };
        let before_attr = head(code, attr.start());
        let between = &code[attr.end()..attr.end() + whole.start()];
        if between.contains(['{', ';']) {
            continue;
        }
        let ignored = before_attr.contains("#[ignore") || between.contains("#[ignore");
        let from = attr.end() + whole.end();
        let Some(open) = code[from..].find('{').map(|p| p + from) else {
            continue;
        };
        let Some(close) = matching(b, open) else {
            continue;
        };
        out.push(TestFn {
            name: name.as_str().to_owned(),
            open,
            close,
            ignored,
        });
    }
    out
}

/// The test functions `src` defines that are not ignored.
fn test_count(src: &str) -> usize {
    test_fns(&source_scan::code_only(src))
        .iter()
        .filter(|t| !t.ignored)
        .count()
}

/// Whether one of `lines` (1-based, inclusive) of `src` carries the marker
/// with a reason after it.
fn marked(src: &str, first: usize, last: usize) -> bool {
    src.lines()
        .skip(first.saturating_sub(1))
        .take(last + 1 - first)
        .any(|line| {
            line.split_once(MARKER)
                .is_some_and(|(_, reason)| !reason.trim().is_empty())
        })
}

/// One function: its name, whether its body calls `test_prereq::`, and the
/// names its body calls (unqualified, qualified).
type Function = (String, bool, BTreeSet<String>, BTreeSet<String>);

/// Every function `src` defines that is not a test.
fn functions(src: &str) -> Vec<Function> {
    let code = source_scan::code_only(src);
    let tests: BTreeSet<usize> = test_fns(&code).iter().map(|t| t.open).collect();
    let b = code.as_bytes();
    let mut out = Vec::new();
    let Some(fns) = FN.as_ref() else {
        return out;
    };
    for f in fns.captures_iter(&code) {
        let (Some(whole), Some(name)) = (f.get(0), f.get(1)) else {
            continue;
        };
        let rest = &code[whole.end()..];
        let (Some(brace), semi) = (rest.find('{'), rest.find(';')) else {
            continue;
        };
        if semi.is_some_and(|s| s < brace) {
            continue;
        }
        let open = whole.end() + brace;
        // A test is never called, so it is never a wrapper.
        if tests.contains(&open) {
            continue;
        }
        let Some(close) = matching(b, open) else {
            continue;
        };
        let body = &code[open..close];
        let (bare, qualified) = calls(body);
        out.push((
            name.as_str().to_owned(),
            body.contains("test_prereq::"),
            bare,
            qualified,
        ));
    }
    out
}

/// Every wrapper across `sources`, to a fixed point: a function whose body
/// calls `test_prereq::`, a wrapper of its own file, or (by a qualified path)
/// a wrapper of a support module.
fn wrappers(sources: &[(String, String)]) -> Wrappers {
    let all: Vec<(&str, Vec<Function>)> = sources
        .iter()
        .map(|(file, src)| (file.as_str(), functions(src)))
        .collect();
    let mut w = Wrappers::default();
    loop {
        let mut changed = false;
        for (file, fns) in &all {
            for (name, direct, bare, qualified) in fns {
                let local = w.local.entry((*file).to_owned()).or_default();
                if local.contains(name) {
                    continue;
                }
                let is_wrapper = *direct
                    || bare.iter().any(|n| local.contains(n))
                    || qualified.iter().any(|n| w.support.contains(n));
                if is_wrapper {
                    local.insert(name.clone());
                    if is_support(file) {
                        w.support.insert(name.clone());
                    }
                    changed = true;
                }
            }
        }
        if !changed {
            return w;
        }
    }
}

/// The refused early returns of `src`, the file `file`.
fn findings(file: &str, src: &str, wrappers: &Wrappers) -> Vec<Finding> {
    let code = source_scan::code_only(src);
    let b = code.as_bytes();
    let mut out = Vec::new();
    for t in test_fns(&code).iter().filter(|t| !t.ignored) {
        // (offset of the block's `{`, whether its returns are another body's)
        let mut stack: Vec<(usize, bool)> = vec![(t.open, false)];
        let mut i = t.open + 1;
        while i < t.close {
            match b[i] {
                b'{' => {
                    let nested = stack.last().is_some_and(|&(_, n)| n) || is_nested(head(&code, i));
                    stack.push((i, nested));
                }
                b'}' => {
                    stack.pop();
                }
                b'r' if code[i..].starts_with("return")
                    && !b[i - 1].is_ascii_alphanumeric()
                    && b[i - 1] != b'_'
                    && !b
                        .get(i + 6)
                        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') =>
                {
                    let Some(&(open, nested)) = stack.last() else {
                        break;
                    };
                    let rest = code[i + 6..].trim_start();
                    let success = rest.starts_with(';') || rest.starts_with("Ok(");
                    let closing = stack.len() == 1
                        && code[i..t.close]
                            .find(';')
                            .is_some_and(|semi| code[i + semi + 1..t.close].trim().is_empty());
                    if !nested && success && !closing {
                        let context = format!("{}{}", head(&code, open), &code[open..i]);
                        let line = line_of(&code, i);
                        if !decides(file, &context, wrappers)
                            && !marked(src, line_of(&code, open), line)
                        {
                            out.push(Finding {
                                file: file.to_owned(),
                                line,
                                test: t.name.clone(),
                            });
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    out
}

/// A fixture's text with its `@test` placeholders made test attributes.
///
/// The raw-string fixtures spell the attribute `@test`:
/// `fixture_isolation_test` refuses a raw string that holds a bare test
/// marker, because naive scanners would count it as a test.
fn fx(src: &str) -> String {
    src.replace("@test", "#[test]")
}

/// The findings of one fixture (`fixture.rs`), with the wrappers it defines.
fn scan(src: &str) -> Vec<Finding> {
    let src = fx(src);
    let sources = vec![("fixture.rs".to_owned(), src.clone())];
    findings("fixture.rs", &src, &wrappers(&sources))
}

/// The lines of `scan(src)`.
fn lines(src: &str) -> Vec<usize> {
    scan(src).iter().map(|f| f.line).collect()
}

const SILENT_EXISTS: &str = r#"
@test
fn needs_dev_full() -> Result<(), TestError> {
    if !Path::new("/dev/full").exists() {
        return Ok(());
    }
    assert!(true, "x");
    Ok(())
}
"#;

const HELPER_ELSE: &str = r#"
@test
fn needs_editcap() -> Result<(), TestError> {
    let Some(editcap) = test_prereq::check("editcap", OPTIONAL, test_prereq::on_path("editcap"))? else {
        return Ok(());
    };
    run(editcap)?;
    Ok(())
}
"#;

const HELPER_MULTILINE: &str = r#"
@test
fn needs_editcap() -> Result<(), TestError> {
    let Some(editcap) = test_prereq::check(
        "editcap",
        OPTIONAL,
        test_prereq::on_path("editcap"),
    )?
    else {
        return Ok(());
    };
    run(editcap)?;
    Ok(())
}
"#;

const HELPER_MATCH_ARM: &str = r#"
@test
fn needs_editcap() -> Result<(), TestError> {
    let editcap = match test_prereq::check("editcap", OPTIONAL, probe())? {
        Some(e) => e,
        None => return Ok(()),
    };
    run(editcap)?;
    Ok(())
}
"#;

const LOCAL_WRAPPER: &str = r#"
fn sudo_or_skip() -> bool {
    test_prereq::present("sudo", OPTIONAL, probe())
}

@test
fn needs_sudo() -> Result<(), TestError> {
    if !sudo_or_skip() {
        return Ok(());
    }
    run()?;
    Ok(())
}
"#;

const TRANSITIVE_WRAPPER: &str = r#"
fn sudo_or_skip() -> bool {
    test_prereq::present("sudo", OPTIONAL, probe())
}

fn root_unavailable(test: &str) -> bool {
    !sudo_or_skip()
}

@test
fn needs_root() -> Result<(), TestError> {
    if root_unavailable("needs_root") {
        return Ok(());
    }
    run()?;
    Ok(())
}
"#;

const NOT_A_WRAPPER: &str = r#"
fn sudo_works() -> bool {
    probe().is_ok()
}

@test
fn needs_sudo() -> Result<(), TestError> {
    if !sudo_works() {
        return Ok(());
    }
    run()?;
    Ok(())
}
"#;

const MARKED: &str = r#"
@test
fn a_child_role() -> Result<(), TestError> {
    if std::env::var_os(ROLE).is_none() {
        // not a prerequisite: the parent test runs this role in a child
        return Ok(());
    }
    run()?;
    Ok(())
}
"#;

const MARKED_ON_HEAD: &str = r#"
@test
fn a_child_role() -> Result<(), TestError> {
    if std::env::var_os(ROLE).is_none() { // not a prerequisite: a child role
        return Ok(());
    }
    run()?;
    Ok(())
}
"#;

const MARKED_WITHOUT_REASON: &str = r#"
@test
fn a_child_role() -> Result<(), TestError> {
    if std::env::var_os(ROLE).is_none() {
        // not a prerequisite:
        return Ok(());
    }
    run()?;
    Ok(())
}
"#;

#[test]
fn success_a_return_on_the_helpers_skip_is_allowed() {
    assert_eq!(
        lines(HELPER_ELSE),
        Vec::<usize>::new(),
        "the helper decided"
    );
    let without = HELPER_ELSE.replace("test_prereq::", "");
    assert_eq!(
        lines(&without),
        vec![5],
        "the same return without the helper is refused"
    );
}

#[test]
fn success_a_return_after_a_multi_line_helper_call_is_allowed() {
    assert_eq!(
        lines(HELPER_MULTILINE),
        Vec::<usize>::new(),
        "the head spans lines"
    );
    let without = HELPER_MULTILINE.replace("test_prereq::", "");
    assert_eq!(
        lines(&without),
        vec![10],
        "without the helper it is refused"
    );
}

#[test]
fn success_a_match_arm_on_the_helper_is_allowed() {
    assert_eq!(
        lines(HELPER_MATCH_ARM),
        Vec::<usize>::new(),
        "the match is on the helper"
    );
    let without = HELPER_MATCH_ARM.replace("test_prereq::check", "check");
    assert_eq!(
        lines(&without),
        vec![6],
        "a match arm return without the helper is refused"
    );
}

#[test]
fn success_a_return_on_a_wrapper_of_the_helper_is_allowed() {
    assert_eq!(
        lines(LOCAL_WRAPPER),
        Vec::<usize>::new(),
        "the wrapper calls the helper"
    );
    let without = LOCAL_WRAPPER.replace("test_prereq::present", "present");
    assert_eq!(
        lines(&without),
        vec![9],
        "a wrapper that does not call it is no wrapper"
    );
}

#[test]
fn success_a_wrapper_of_a_wrapper_is_a_wrapper() {
    assert_eq!(
        lines(TRANSITIVE_WRAPPER),
        Vec::<usize>::new(),
        "wrappers are transitive"
    );
    let without = TRANSITIVE_WRAPPER.replace("test_prereq::present", "present");
    assert_eq!(
        lines(&without),
        vec![13],
        "a chain that never reaches the helper is refused"
    );
}

#[test]
fn success_a_wrapper_in_another_file_is_a_wrapper() {
    let support = "pub fn root() -> Option<PathBuf> {\n    test_prereq::check(\"corpus\", OPTIONAL, env()).ok().flatten()\n}\n";
    let test = "#[test]\nfn reads_the_corpus() -> Result<(), TestError> {\n    let Some(root) = corpus::root() else {\n        return Ok(());\n    };\n    run(root)?;\n    Ok(())\n}\n";
    let sources = vec![
        ("tests/support/corpus.rs".to_owned(), support.to_owned()),
        ("t.rs".to_owned(), test.to_owned()),
    ];
    assert_eq!(
        findings("t.rs", test, &wrappers(&sources)),
        Vec::new(),
        "the wrapper set spans files"
    );
    assert_eq!(
        findings("t.rs", test, &wrappers(&sources[1..])).len(),
        1,
        "without the support file the call is no wrapper"
    );
}

#[test]
fn failure_a_wrapper_in_another_test_file_does_not_excuse_a_return() {
    let other = "fn sample() -> bool {\n    test_prereq::present(\"sudo\", OPTIONAL, p())\n}\n";
    let test = "#[test]\nfn reads() -> Result<(), TestError> {\n    if !sample() {\n        return Ok(());\n    }\n    Ok(())\n}\n";
    let sources = vec![
        ("tests/other_test.rs".to_owned(), other.to_owned()),
        ("tests/t_test.rs".to_owned(), test.to_owned()),
    ];
    assert_eq!(
        findings("tests/t_test.rs", test, &wrappers(&sources)).len(),
        1,
        "a function of the same name in another test file is not this file's wrapper"
    );
}

#[test]
fn failure_a_support_wrapper_called_unqualified_is_not_a_wrapper() {
    let support = "pub fn root() -> Option<PathBuf> {\n    test_prereq::check(\"corpus\", OPTIONAL, env()).ok().flatten()\n}\n";
    let test = "#[test]\nfn reads() -> Result<(), TestError> {\n    let Some(r) = root() else {\n        return Ok(());\n    };\n    run(r)?;\n    Ok(())\n}\n";
    let sources = vec![
        ("tests/support/corpus.rs".to_owned(), support.to_owned()),
        ("tests/t_test.rs".to_owned(), test.to_owned()),
    ];
    assert_eq!(
        findings("tests/t_test.rs", test, &wrappers(&sources)).len(),
        1,
        "a bare `root()` names this file's function, not the support module's"
    );
}

#[test]
fn success_a_marked_return_is_allowed() {
    assert_eq!(lines(MARKED), Vec::<usize>::new(), "the marker says why");
    let without = MARKED.replace(MARKER, "the parent runs this");
    assert_eq!(lines(&without), vec![6], "without the marker it is refused");
}

#[test]
fn success_a_marker_on_the_blocks_opening_line_is_allowed() {
    assert_eq!(
        lines(MARKED_ON_HEAD),
        Vec::<usize>::new(),
        "the marker is in the block"
    );
    let without = MARKED_ON_HEAD.replace(MARKER, "a role");
    assert_eq!(lines(&without), vec![5], "without the marker it is refused");
}

#[test]
fn success_a_return_inside_a_closure_is_not_the_tests() {
    let src = "#[test]\nfn spawns() -> Result<(), TestError> {\n    let h = std::thread::spawn(move || {\n        if x.is_err() {\n            return;\n        }\n    });\n    if !h.is_ok() {\n        return Ok(());\n    }\n    Ok(())\n}\n";
    assert_eq!(lines(src), vec![9], "only the test's own return is refused");
}

#[test]
fn success_a_return_inside_a_nested_fn_is_not_the_tests() {
    let src = "#[test]\nfn nests() -> Result<(), TestError> {\n    fn inner() -> Result<(), TestError> {\n        if x() {\n            return Ok(());\n        }\n        Ok(())\n    }\n    if !y() {\n        return Ok(());\n    }\n    inner()\n}\n";
    assert_eq!(
        lines(src),
        vec![10],
        "the nested fn's return is not the test's"
    );
}

#[test]
fn success_an_ignored_test_is_not_scanned() {
    let ignored = fx(SILENT_EXISTS).replace("#[test]", "#[test]\n#[ignore = \"child role\"]");
    assert_eq!(
        lines(&ignored),
        Vec::<usize>::new(),
        "an ignored test reports ignored"
    );
    assert_eq!(test_count(&ignored), 0, "and is not counted as a test");
    assert_eq!(
        test_count(&fx(SILENT_EXISTS)),
        1,
        "the same test unignored is counted"
    );
}

#[test]
fn success_a_closing_return_is_not_early() {
    let src = "#[test]\nfn ends() {\n    run();\n    return;\n}\n";
    assert_eq!(
        lines(src),
        Vec::<usize>::new(),
        "a return that ends the body skips nothing"
    );
    let early = "#[test]\nfn ends() {\n    return;\n    run();\n}\n";
    assert_eq!(
        lines(early),
        vec![3],
        "a return with code after it is early"
    );
}

#[test]
fn success_an_error_return_is_not_a_skip() {
    let src = "#[test]\nfn fails() -> Result<(), TestError> {\n    if x() {\n        return Err(\"no\".into());\n    }\n    Ok(())\n}\n";
    assert_eq!(
        lines(src),
        Vec::<usize>::new(),
        "returning an error fails the test"
    );
    let success = src.replace("Err(\"no\".into())", "Ok(())");
    assert_eq!(
        lines(&success),
        vec![4],
        "the same return with success is refused"
    );
}

#[test]
fn success_an_async_test_is_scanned_like_any_other() {
    let src = fx(SILENT_EXISTS).replace(
        "#[test]\nfn needs_dev_full()",
        "#[tokio::test]\nasync fn needs_dev_full()",
    );
    assert_eq!(lines(&src), vec![5], "a tokio test is a test");
}

#[test]
fn failure_a_silent_return_on_a_missing_file_is_refused() {
    assert_eq!(lines(SILENT_EXISTS), vec![5], "the /dev/full shape");
}

#[test]
fn failure_a_printed_skip_is_refused() {
    let src = "#[test]\nfn needs_editcap() -> Result<(), TestError> {\n    if Command::new(\"editcap\").output().is_err() {\n        eprintln!(\"editcap not installed — skipping\");\n        return Ok(());\n    }\n    Ok(())\n}\n";
    assert_eq!(
        lines(src),
        vec![5],
        "a notice libtest discards does not make it a skip"
    );
}

#[test]
fn failure_a_let_else_on_a_probe_is_refused() {
    let src = "#[test]\nfn needs_home() -> Result<(), TestError> {\n    let Ok(home) = std::env::var(\"HOME\") else {\n        return Ok(());\n    };\n    run(home)?;\n    Ok(())\n}\n";
    assert_eq!(lines(src), vec![4], "the let-else shape");
}

#[test]
fn failure_a_match_arm_return_is_refused() {
    let src = "#[test]\nfn needs_raw() -> Result<(), TestError> {\n    let raw = match open() {\n        Ok(s) => s,\n        Err(_) => return Ok(()),\n    };\n    run(raw)?;\n    Ok(())\n}\n";
    assert_eq!(lines(src), vec![5], "a match arm without braces");
}

#[test]
fn failure_a_bare_return_in_a_unit_test_is_refused() {
    let src =
        "#[test]\nfn needs_tar() {\n    if !have_tar() {\n        return;\n    }\n    run();\n}\n";
    assert_eq!(lines(src), vec![4], "`return;` in a test without a result");
}

#[test]
fn failure_a_marker_without_a_reason_is_refused() {
    assert_eq!(
        lines(MARKED_WITHOUT_REASON),
        vec![6],
        "the marker must say why"
    );
}

#[test]
fn failure_a_guard_that_does_not_call_the_helper_is_refused() {
    assert_eq!(
        lines(NOT_A_WRAPPER),
        vec![9],
        "a probe of its own is not the helper"
    );
}

#[test]
fn failure_the_helper_named_in_a_comment_or_string_does_not_count() {
    let src = "#[test]\nfn needs_x() -> Result<(), TestError> {\n    // test_prereq::check would go here\n    if !x(\"test_prereq::check\") {\n        return Ok(());\n    }\n    Ok(())\n}\n";
    assert_eq!(lines(src), vec![5], "only code names the helper");
}

#[test]
fn failure_a_platform_return_at_the_top_of_the_body_is_refused() {
    let src = "#[test]\nfn linux_only() -> Result<(), TestError> {\n    #[cfg(not(target_os = \"linux\"))]\n    return Ok(());\n    run()?;\n    Ok(())\n}\n";
    assert_eq!(
        lines(src),
        vec![4],
        "a cfg return with code after it is early"
    );
}

#[test]
fn failure_only_the_innermost_block_decides() {
    let src = "#[test]\nfn two() -> Result<(), TestError> {\n    let Some(x) = test_prereq::check(\"sudo\", OPTIONAL, p())? else {\n        return Ok(());\n    };\n    if !x.ready() {\n        return Ok(());\n    }\n    Ok(())\n}\n";
    assert_eq!(lines(src), vec![7], "a later guard needs its own decision");
}

#[test]
fn failure_a_wrapper_name_must_match_whole() {
    let src = format!(
        "{LOCAL_WRAPPER}\n#[test]\nfn other() -> Result<(), TestError> {{\n    if !my_sudo_or_skip() {{\n        return Ok(());\n    }}\n    Ok(())\n}}\n"
    );
    assert_eq!(
        lines(&src),
        vec![18],
        "`my_sudo_or_skip` is not `sudo_or_skip`"
    );
}

#[test]
fn edge_braces_in_strings_do_not_end_the_body() {
    let src = "#[test]\nfn braces() -> Result<(), TestError> {\n    let s = \"}}}\";\n    if s.is_empty() {\n        return Ok(());\n    }\n    Ok(())\n}\n";
    assert_eq!(lines(src), vec![5], "a string's braces are not code");
}

#[test]
fn edge_a_test_attribute_in_a_comment_is_not_a_test() {
    let src = "// #[test]\nfn helper() {\n    if x() {\n        return;\n    }\n    y();\n}\n";
    assert_eq!(
        lines(src),
        Vec::<usize>::new(),
        "a comment is not an attribute"
    );
    assert_eq!(test_count(src), 0, "and counts no test");
    let real = src.replace("// #[test]", "#[test]");
    assert_eq!(
        lines(&real),
        vec![4],
        "the same fn under a real attribute is scanned"
    );
}

#[test]
fn edge_a_finding_names_its_file_line_and_test() {
    let found = findings("tests/x_test.rs", &fx(SILENT_EXISTS), &Wrappers::default());
    assert_eq!(
        found,
        vec![Finding {
            file: "tests/x_test.rs".to_owned(),
            line: 5,
            test: "needs_dev_full".to_owned(),
        }],
        "file, line and test"
    );
}

#[test]
fn edge_each_test_in_a_file_is_reported() {
    let src = format!(
        "{SILENT_EXISTS}{}",
        SILENT_EXISTS.replace("needs_dev_full", "second")
    );
    let names: Vec<String> = scan(&src).into_iter().map(|f| f.test).collect();
    assert_eq!(names, vec!["needs_dev_full", "second"], "both tests");
}

#[test]
fn edge_a_helper_call_after_the_return_does_not_excuse_it() {
    let src = "#[test]\nfn late() -> Result<(), TestError> {\n    if !x() {\n        return Ok(());\n    }\n    test_prereq::check(\"sudo\", OPTIONAL, p())?;\n    Ok(())\n}\n";
    assert_eq!(
        lines(src),
        vec![4],
        "the decision must come before the return"
    );
}

#[test]
fn edge_a_test_with_attributes_between_test_and_fn_is_found() {
    let src = fx(SILENT_EXISTS).replace(
        "#[test]",
        "#[test]\n#[cfg(target_os = \"linux\")]\n#[allow(clippy::x)]",
    );
    assert_eq!(
        lines(&src),
        vec![7],
        "attributes between `#[test]` and `fn`"
    );
}

/// Every `.rs` file under `dir`, as `(path relative to the repo, text)`.
fn rust_files(repo: &Path, dir: &str) -> Result<Vec<(String, String)>, TestError> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(repo.join(dir)) {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "rs") {
            let rel = path
                .strip_prefix(repo)?
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, std::fs::read_to_string(path)?));
        }
    }
    Ok(out)
}

#[test]
fn every_pattern_the_gate_uses_compiles() {
    for (name, pattern) in [
        ("NESTED", &NESTED),
        ("CALL", &CALL),
        ("ATTR", &ATTR),
        ("FN", &FN),
    ] {
        assert!(
            pattern.is_some(),
            "{name} does not compile, so the scanner would read nothing"
        );
    }
}

#[test]
fn no_test_returns_early_without_the_prerequisite_helper() -> Result<(), TestError> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut sources = rust_files(&repo, "tests")?;
    sources.extend(rust_files(&repo, "src")?);
    assert!(
        sources.len() >= MIN_FILES,
        "the walk found {} source files, fewer than {MIN_FILES}: it lost a directory",
        sources.len()
    );
    let tests: usize = sources.iter().map(|(_, s)| test_count(s)).sum();
    assert!(
        tests >= MIN_TESTS,
        "the scan found {tests} tests, fewer than {MIN_TESTS}: the test finder broke"
    );
    let known = wrappers(&sources);
    let found: Vec<String> = sources
        .iter()
        .flat_map(|(file, src)| findings(file, src, &known))
        .map(|f| f.to_string())
        .collect();
    assert!(
        found.is_empty(),
        "{} early success returns in tests are not decided by src/test_prereq.rs. \
         Ask for the prerequisite with test_prereq::check / required / present, or, \
         when the return is no prerequisite skip, say why with `// {MARKER} <reason>`:\n{}",
        found.len(),
        found.join("\n")
    );
    Ok(())
}

#[test]
fn the_ci_require_list_names_only_known_prerequisites() -> Result<(), TestError> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ci = std::fs::read_to_string(repo.join(".github/workflows/ci.yml"))?;
    let assignment = format!("{}=", test_prereq::REQUIRE_VAR);
    let mut names = BTreeSet::new();
    let mut lists = 0usize;
    for line in ci.lines() {
        let Some((_, rest)) = line.split_once(&assignment) else {
            continue;
        };
        let value: String = rest
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ';')
            .collect();
        if value.is_empty() {
            continue;
        }
        lists += 1;
        names.extend(
            value
                .split(',')
                .filter(|n| !n.is_empty())
                .map(str::to_owned),
        );
    }
    assert!(
        lists >= 2,
        "ci.yml sets {} for the Linux and the macOS suite, so CI fails when a \
         prerequisite its runners have goes missing; found {lists} lists",
        test_prereq::REQUIRE_VAR
    );
    let unknown: Vec<&String> = names
        .iter()
        .filter(|n| n.as_str() != "all" && !test_prereq::KNOWN.contains(&n.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "ci.yml requires names no test asks for: {unknown:?}"
    );
    Ok(())
}
