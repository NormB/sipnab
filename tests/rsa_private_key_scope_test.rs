// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every statement of where sipnab uses an `rsa` private key names every place
//! that does.
//!
//! RUSTSEC-2023-0071 (the "Marvin" timing side channel in the `rsa` crate) has
//! no fixed release, and sipnab keeps an exemption for it in `deny.toml`, in
//! CI's `cargo audit` step and in its VEX statement. Each of those, and the
//! vCon how-to, gives the reason: where a private-key operation happens and why
//! no remote party can time it. On 2026-11-05 all three exemption texts said
//! the crate was used for `--tls-key` alone, while `src/output/vcon_jose.rs`
//! also decrypts with it. A new call site would go just as unnoticed.
//!
//! One rule decides the list: a file under `src/` whose production code (the
//! part before its test module, comments removed) names `RsaPrivateKey`, the
//! type every private-key operation of the crate needs. Each document must name
//! each such file by its path.

use std::path::{Path, PathBuf};

#[path = "support/source_scan.rs"]
mod source_scan;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The documents that state where the private key is used.
const STATEMENTS: [&str; 5] = [
    "deny.toml",
    "osv-scanner.toml",
    ".github/workflows/ci.yml",
    "vex/sipnab.openvex.json",
    "docs/vcon.md",
];

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `dir`, sorted.
fn rs_files(dir: &Path) -> Result<Vec<PathBuf>, TestError> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|x| x == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Whether the production code of `src` names `RsaPrivateKey`.
fn uses_an_rsa_private_key(src: &str) -> bool {
    source_scan::production_source(src)
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .any(|code| code.contains("RsaPrivateKey"))
}

/// The repository-relative paths of the files that use an `rsa` private key.
fn private_key_users() -> Result<Vec<String>, TestError> {
    let root = repo();
    let mut users = Vec::new();
    for path in rs_files(&root.join("src"))? {
        if uses_an_rsa_private_key(&std::fs::read_to_string(&path)?) {
            let rel = path.strip_prefix(&root)?.to_string_lossy().into_owned();
            users.push(rel);
        }
    }
    Ok(users)
}

/// Each statement names every file that uses an `rsa` private key.
#[test]
fn every_rsa_exemption_statement_names_every_private_key_user() -> Result<(), TestError> {
    let users = private_key_users()?;
    // Anti-vacuity: the rule finds the two users this test was written
    // against. Fewer means the walk or the rule broke.
    assert!(
        users.len() >= 2,
        "the rule found only {users:?}; it is not checking what it claims to"
    );
    let mut missing = Vec::new();
    for doc in STATEMENTS {
        let text = std::fs::read_to_string(repo().join(doc))?;
        for user in &users {
            if !text.contains(user.as_str()) {
                missing.push(format!("{doc} does not name {user}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "a statement of where sipnab uses an `rsa` private key leaves one out:\n  {}",
        missing.join("\n  ")
    );
    Ok(())
}

/// The rule itself: a private key named in code counts, one named only in a
/// comment or only in the test module does not.
#[test]
fn the_rule_reads_code_not_comments_or_tests() {
    assert!(
        uses_an_rsa_private_key("use rsa::RsaPrivateKey;\n"),
        "a use of the type in code counts"
    );
    assert!(
        !uses_an_rsa_private_key("// RsaPrivateKey is not used here\nfn f() {}\n"),
        "a mention in a comment does not count"
    );
    assert!(
        !uses_an_rsa_private_key(
            "fn f() {}\n#[cfg(test)]\nmod tests {\n    use rsa::RsaPrivateKey;\n}\n"
        ),
        "a use in the test module does not count"
    );
}

/// The VEX statement for the advisory says `affected`, as decided on
/// 2026-11-05: the risk is low, not zero, because with `--vcon-fetch` the
/// store chooses the ciphertext. OpenVEX requires an `action_statement` for
/// `affected`, and it must give the two ways out.
#[test]
fn the_vex_statement_is_affected_and_says_what_to_do() -> Result<(), TestError> {
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        repo().join("vex/sipnab.openvex.json"),
    )?)?;
    let statement = doc["statements"]
        .as_array()
        .ok_or("statements is an array")?
        .iter()
        .find(|s| s["vulnerability"]["name"] == "RUSTSEC-2023-0071")
        .ok_or("no statement for RUSTSEC-2023-0071")?;
    assert_eq!(
        statement["status"].as_str(),
        Some("affected"),
        "RUSTSEC-2023-0071 is stated as affected, not {}",
        statement["status"]
    );
    let action = statement["action_statement"].as_str().unwrap_or_default();
    for needle in ["EC P-256", "trust", "--vcon-fetch"] {
        assert!(
            action.contains(needle),
            "the action statement names {needle:?}: {action:?}"
        );
    }
    assert!(
        statement["justification"].is_null(),
        "a justification belongs to not_affected only"
    );
    Ok(())
}
