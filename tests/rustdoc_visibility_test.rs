//! Public documentation must not link to items rustdoc cannot reach.
//!
//! `cargo doc` with `RUSTDOCFLAGS="-D warnings"` refuses a `pub` item whose
//! docs carry an intra-doc link to a private or `pub(crate)` item, because the
//! rendered page would show a link the reader cannot follow. That check lives
//! in the pre-push hook and in CI's Docs step -- not in pre-commit, which is
//! the gap these tests close. Two doc links added to `capture_hep` sailed
//! through a full green pre-commit run, including its own 15-minute suite, and
//! were caught only when `git push` ran the hook ten minutes later.
//!
//! The cost is not the ten minutes. It is that the commit was already made, so
//! the fix arrives as a second commit against work that was reported finished.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/`.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo().join("src"), &mut out);
    out.sort();
    out
}

/// Whether an item declaration line makes the item public *outside the crate*.
///
/// `pub(crate)` and `pub(super)` are deliberately NOT public here. That is the
/// whole point: rustdoc treats them exactly as it treats a bare private item
/// when a `pub` item's documentation links to one, and `hep_stream_frame` --
/// one of the two links that blocked the push -- was `pub(crate)`. A checker
/// that accepted any leading `pub` would have called that link fine.
fn is_public(decl: &str) -> bool {
    let t = decl.trim_start();
    t.starts_with("pub ") || t.starts_with("pub\t")
}

/// Item name and whether it is publicly visible, for every item declared in
/// one file.
///
/// Keyed by name, so a file declaring two items with one name (an inherent
/// method and a free function, say) keeps the last -- acceptable because the
/// question asked of this map is only ever "is there a NON-public item by this
/// name here", and a collision that hides a private one would make the gate
/// quieter, never louder.
fn declarations(text: &str) -> BTreeMap<String, bool> {
    let kinds = [
        "fn",
        "struct",
        "enum",
        "trait",
        "const",
        "static",
        "type",
        "union",
        "macro_rules!",
    ];
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let t = line.trim_start();
        // Skip the visibility prefix to find the kind keyword, remembering
        // whether that prefix made it public.
        let public = is_public(t);
        let rest = t
            .strip_prefix("pub(crate) ")
            .or_else(|| t.strip_prefix("pub(super) "))
            .or_else(|| t.strip_prefix("pub(self) "))
            .or_else(|| t.strip_prefix("pub "))
            .unwrap_or(t);
        // `async`, `unsafe`, `extern "C"` and `const` may sit between the
        // visibility and the kind.
        let rest = rest
            .trim_start_matches("default ")
            .trim_start_matches("const ")
            .trim_start_matches("async ")
            .trim_start_matches("unsafe ")
            .trim_start_matches("extern \"C\" ")
            .trim_start_matches("extern \"Rust\" ");
        for kind in kinds {
            let Some(after) = rest.strip_prefix(kind) else {
                continue;
            };
            let Some(after) = after.strip_prefix([' ', '\t']) else {
                continue;
            };
            let name: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.insert(name, public);
            }
            break;
        }
    }
    out
}

/// One documented item: the doc lines above it and the line declaring it.
struct Documented {
    line_no: usize,
    doc: String,
    decl: String,
    /// `#[doc(hidden)]` sat between the docs and the declaration.
    ///
    /// Such an item is not rendered, so rustdoc never resolves its links and
    /// this gate must not either -- rustdoc is the authority, and a gate that
    /// demanded more than the authority would be unfixable except by weakening
    /// documentation nobody reads. `rtp::rtcp::compact_ntp_for_test` is the
    /// real instance: `pub` inside a `pub mod`, hidden, and its docs open by
    /// naming the private `compact_ntp` it wraps.
    hidden: bool,
}

/// Every item in a file that carries `///` documentation.
///
/// Attributes between the docs and the declaration are stepped over -- a
/// `#[derive]` or `#[allow]` does not end a doc block -- but a blank line
/// does, because a `///` block separated from its item by a blank line is not
/// attached to it at all. That is the same attachment rule
/// `attribute_attachment_test` exists to police, and reading it differently
/// here would make the two gates disagree about what a doc comment belongs to.
fn documented_items(text: &str) -> Vec<Documented> {
    let mut out = Vec::new();
    let mut doc: Vec<&str> = Vec::new();
    let mut doc_start = 0usize;
    let mut hidden = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("///") {
            if doc.is_empty() {
                doc_start = i + 1;
                hidden = false;
            }
            doc.push(rest);
        } else if doc.is_empty() {
            continue;
        } else if t.starts_with("#[") || t.starts_with("#![") {
            // An attribute keeps the block open, but `#[doc(hidden)]` decides
            // whether rustdoc will ever look at what follows.
            if t.replace(' ', "").starts_with("#[doc(hidden)") {
                hidden = true;
            }
        } else if t.is_empty() {
            // A blank line detaches the block from whatever comes next.
            doc.clear();
        } else {
            out.push(Documented {
                line_no: doc_start,
                doc: doc.join("\n"),
                decl: line.to_string(),
                hidden,
            });
            doc.clear();
        }
    }
    out
}

/// The unqualified intra-doc link targets in one doc block.
///
/// Only the ``[`Name`]`` form, and only when no `(target)` follows it: a
/// ``[`x`](https://…)`` is an ordinary markdown link whose destination rustdoc
/// never resolves, and flagging those would make this gate fire on every
/// citation in the tree. Qualified paths (`signals::shutdown_requested`,
/// `Self::send`) are skipped because they resolve somewhere other than this
/// file, and this gate only claims to know what this file declares.
///
/// Fenced blocks inside the doc comment are skipped, so a `[`x`]` shown as
/// example prose in a doctest is not read as a link.
fn intra_doc_links(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    for line in doc.lines() {
        // Tolerate a leading `///`: `documented_items` hands over stripped
        // content, but a caller reading raw source lines must see the same
        // fences, or an example block would be scanned as prose.
        let t = line.trim_start().trim_start_matches("///").trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let bytes: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i + 2 < bytes.len() {
            if bytes[i] == '[' && bytes[i + 1] == '`' {
                let mut j = i + 2;
                let mut name = String::new();
                while j < bytes.len() && bytes[j] != '`' {
                    name.push(bytes[j]);
                    j += 1;
                }
                // Require the closing "`]" and no "(" immediately after.
                let closed = j + 1 < bytes.len() && bytes[j] == '`' && bytes[j + 1] == ']';
                let linked = closed && bytes.get(j + 2) != Some(&'(');
                if linked
                    && !name.contains("::")
                    && !name.contains(' ')
                    && !name.is_empty()
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    out.push(name);
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }
    }
    out
}

/// A `pub` item's documentation never links to a private or `pub(crate)` item
/// declared beside it.
///
/// This is the defect rustdoc rejected on `capture_hep`: it is `pub`, and its
/// docs linked ``[`HepIngest`]`` (a private struct) and ``[`hep_stream_frame`]``
/// (`pub(crate)`). Both are the right things to NAME in that prose -- they are
/// what the function's behavior is made of -- so the fix is to name them in a
/// code span rather than a link, not to make them public to satisfy a linker.
///
/// Scoped to names declared in the SAME file, which is what makes it cheap and
/// keeps it honest: it never guesses at cross-module resolution, so a link it
/// passes may still be wrong and rustdoc remains the authority. What it buys
/// is the common case, in the seconds before a commit rather than the minutes
/// after one.
#[test]
fn public_docs_do_not_link_to_items_rustdoc_cannot_reach() {
    let mut offences: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut links_seen = 0usize;

    for path in source_files() {
        let text = std::fs::read_to_string(&path).expect("read source");
        let decls = declarations(&text);
        for item in documented_items(&text) {
            if !is_public(&item.decl) || item.hidden {
                continue;
            }
            scanned += 1;
            for name in intra_doc_links(&item.doc) {
                links_seen += 1;
                if let Some(false) = decls.get(&name) {
                    offences.push(format!(
                        "{}:{} — public `{}` links to `{}`, which is not public here",
                        path.strip_prefix(repo()).unwrap_or(&path).display(),
                        item.line_no,
                        item.decl.trim(),
                        name
                    ));
                }
            }
        }
    }

    // An extractor that stopped matching would report zero offences and look
    // exactly like a clean tree. Prove it still sees the shapes it reads.
    assert!(
        scanned > 500,
        "only {scanned} documented public items found — the item scanner stopped matching"
    );
    assert!(
        links_seen > 100,
        "only {links_seen} intra-doc links found — the link extractor stopped matching"
    );

    assert!(
        offences.is_empty(),
        "public documentation links to items rustdoc cannot reach:\n  {}\n\
         Name them in a code span (`Foo`) instead of a link ([`Foo`]), or make \
         the target public if it genuinely belongs to the public API.",
        offences.join("\n  ")
    );
}

/// The scanner reads a real tree, and can tell a public link from a private
/// one.
///
/// Without this the gate above could pass because every helper returned
/// nothing. Each half is driven with material shaped like the defect.
#[test]
fn the_visibility_scanner_distinguishes_what_rustdoc_distinguishes() {
    let sample = "\
/// Doc for a private struct.
struct HepIngest;

/// Doc for a crate-visible fn.
pub(crate) fn hep_stream_frame() {}

/// Doc for a public fn.
pub fn capture_hep() {}
";
    let decls = declarations(sample);
    assert_eq!(
        decls.get("HepIngest"),
        Some(&false),
        "a bare `struct` is not public"
    );
    assert_eq!(
        decls.get("hep_stream_frame"),
        Some(&false),
        "`pub(crate)` is not public to rustdoc's eye, which is the case that \
         caught us"
    );
    assert_eq!(decls.get("capture_hep"), Some(&true), "`pub fn` is public");

    assert_eq!(
        intra_doc_links("/// see [`HepIngest`] and [`hep_stream_frame`]")
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["HepIngest", "hep_stream_frame"],
        "both intra-doc links are read"
    );
    assert!(
        intra_doc_links("/// see [`x`](https://example.invalid/)").is_empty(),
        "a markdown link with a target is not an intra-doc link"
    );
    assert!(
        intra_doc_links("/// see [`signals::shutdown_requested`]").is_empty(),
        "a qualified path resolves outside this file, so it is not judged here"
    );
    assert!(
        intra_doc_links("/// ```\n/// [`NotALink`]\n/// ```").is_empty(),
        "a fenced example is content, not a link"
    );

    assert_eq!(
        documented_items(sample).len(),
        3,
        "all three documented items are found"
    );
    assert!(
        documented_items(sample).iter().all(|d| !d.hidden),
        "nothing in the sample is hidden"
    );

    // The one exclusion this gate makes, driven rather than asserted in prose.
    // Without it the gate is stricter than rustdoc, and a gate stricter than
    // its own authority is unfixable except by damaging documentation.
    let hidden_sample = "\
/// Wraps the private one for tests in sibling modules.
#[doc(hidden)]
#[must_use]
pub fn compact_ntp_for_test() {}
";
    let found = documented_items(hidden_sample);
    assert_eq!(found.len(), 1, "the hidden item is still parsed");
    assert!(
        found[0].hidden,
        "`#[doc(hidden)]` between the docs and the declaration must be seen, \
         even with another attribute after it -- rustdoc renders no page for \
         this item and so resolves none of its links"
    );
}

/// The pre-push hook still runs rustdoc with warnings denied.
///
/// This gate is only as good as the authority behind it: the scanner above
/// judges one file at a time and says so, and rustdoc is what actually decides.
/// If the hook's Docs step were dropped or softened to a warning, nothing else
/// in the repo would notice -- pre-commit does not run `cargo doc` at all.
#[test]
fn the_pre_push_hook_still_denies_rustdoc_warnings() {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-push"))
        .expect("the pre-push hook is readable");

    let invocation = hook
        .lines()
        .find(|l| {
            l.contains("cargo doc") && l.contains("RUSTDOCFLAGS") && l.trim().starts_with("if")
        })
        .unwrap_or_else(|| {
            panic!(
                "the pre-push hook no longer runs `cargo doc` under RUSTDOCFLAGS as a \
                 condition — without it, a private intra-doc link reaches CI"
            )
        });

    assert!(
        invocation.contains("-D warnings"),
        "the hook runs cargo doc but no longer denies warnings, so a broken \
         intra-doc link would merely print: {invocation}"
    );
    assert!(
        invocation.contains("--all-features"),
        "the hook must document all features, or a link inside a feature-gated \
         item is never resolved: {invocation}"
    );
}
