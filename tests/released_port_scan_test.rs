// SPDX-License-Identifier: MIT OR Apache-2.0

//! No test under `tests/` reserves a port by binding `:0`, reading the
//! number, and releasing the socket.
//!
//! Between the release and the use, a test running alongside that binds `:0`
//! can be handed the same number and listen on it. A test that needs a port
//! where a connection is refused holds one with
//! `support/ports.rs::refused_tcp_port` instead.
//!
//! Two shapes are recognized, both on a loopback or unspecified address with
//! port 0 written as a literal (`"127.0.0.1:0"`, `("127.0.0.1", 0)`,
//! `(Ipv4Addr::LOCALHOST, 0)` and the like):
//!
//! * the socket is a temporary: `bind(..)?.local_addr()` in one statement, so
//!   it is closed as soon as the statement ends;
//! * the socket is named, its address is read, and it is then passed to
//!   `drop(..)`.
//!
//! A test that keeps its socket bound and uses it matches neither.

use std::path::{Path, PathBuf};

use regex::Regex;

/// Any error, boxed, so `?` works on every error type alike.
type TestError = Box<dyn std::error::Error>;

/// A loopback or unspecified address with port 0, as a string or a tuple.
const ADDR: &str = r#"(?:"(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1?\]):0"|\(\s*(?:"(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1?)"|(?:std::net::)?Ipv[46]Addr::(?:LOCALHOST|UNSPECIFIED)|\[\s*127\s*,\s*0\s*,\s*0\s*,\s*1\s*\])\s*,\s*0\s*\))"#;

/// The 1-based line of every reserve-then-release site in `src`.
fn released_port_sites(src: &str) -> Result<Vec<usize>, TestError> {
    let bind = Regex::new(&format!(r"\bbind\(\s*{ADDR}\s*\)"))?;
    // What may sit between the bind call and `.local_addr()` when the socket
    // is never named: `?`, and the usual unwrapping calls.
    let chained = Regex::new(
        r"\A(?:\s|\?|\.(?:ok|unwrap)\(\)|\.(?:expect|map_err)\((?:[^()]|\([^()]*\))*\))*\.local_addr\(\)",
    )?;
    let named = Regex::new(&format!(
        r"\blet\s+(?:mut\s+)?([a-z_][a-z0-9_]*)\s*(?::\s*[^=;]+)?=\s*(?:[\w:]+::)?bind\(\s*{ADDR}\s*\)"
    ))?;

    let line_of = |offset: usize| src[..offset].matches('\n').count() + 1;
    let mut lines = Vec::new();
    for m in bind.find_iter(src) {
        if chained.is_match(&src[m.end()..]) {
            lines.push(line_of(m.start()));
        }
    }
    for caps in named.captures_iter(src) {
        let (Some(whole), Some(name)) = (caps.get(0), caps.get(1)) else {
            continue;
        };
        let rest = &src[whole.end()..block_end(src, whole.end())];
        let name = regex::escape(name.as_str());
        // A later `let` of the same name starts a different socket.
        let rest = match Regex::new(&format!(r"\blet\s+(?:mut\s+)?{name}\b"))?.find(rest) {
            Some(shadow) => &rest[..shadow.start()],
            None => rest,
        };
        let Some(read) = Regex::new(&format!(r"\b{name}\s*\.local_addr\(\)"))?.find(rest) else {
            continue;
        };
        if Regex::new(&format!(r"\bdrop\(\s*{name}\s*\)"))?.is_match(&rest[read.end()..]) {
            lines.push(line_of(whole.start()));
        }
    }
    lines.sort_unstable();
    lines.dedup();
    Ok(lines)
}

/// The offset where the block enclosing `from` closes, or the end of `src`.
fn block_end(src: &str, from: usize) -> usize {
    let mut depth = 0usize;
    for (i, c) in src[from..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth == 0 => return from + i,
            '}' => depth -= 1,
            _ => {}
        }
    }
    src.len()
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), TestError> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn a_temporary_socket_whose_port_is_read_is_found() -> Result<(), TestError> {
    let src =
        "fn t() {\n    let port = TcpListener::bind(\"127.0.0.1:0\")?.local_addr()?.port();\n}\n";
    assert_eq!(released_port_sites(src)?, [2]);
    Ok(())
}

#[test]
fn a_temporary_socket_across_lines_and_address_forms_is_found() -> Result<(), TestError> {
    let src = "let a = std::net::TcpListener::bind((\"127.0.0.1\", 0))\n    \
               .map_err(|e| format!(\"bind {e}\"))?\n    .local_addr()?;\n\
               let b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?;\n\
               let c = TcpListener::bind(\"[::1]:0\").ok()?.local_addr().ok()?;\n";
    assert_eq!(released_port_sites(src)?, [1, 4, 5]);
    Ok(())
}

#[test]
fn a_named_socket_dropped_after_its_port_is_read_is_found() -> Result<(), TestError> {
    let src = "fn t() {\n    let closed = std::net::TcpListener::bind(\"127.0.0.1:0\")?;\n    \
               let port = closed.local_addr()?.port();\n    drop(closed);\n}\n";
    assert_eq!(released_port_sites(src)?, [2]);
    Ok(())
}

/// The negative controls: a socket kept for the test's lifetime, one whose
/// address is passed straight to a connect, and one dropped without its port
/// ever being read are not the defect.
#[test]
fn a_socket_that_is_kept_or_never_read_is_not_found() -> Result<(), TestError> {
    let src = "fn t() {\n    let l = TcpListener::bind(\"127.0.0.1:0\")?;\n    \
               let port = l.local_addr()?.port();\n    serve(&l, port);\n}\n\
               fn u() {\n    let l = TcpListener::bind(\"127.0.0.1:0\")?;\n    \
               let c = TcpStream::connect(l.local_addr()?)?;\n    let _ = (l, c);\n}\n\
               fn v() {\n    let s = UdpSocket::bind(\"127.0.0.1:0\")?;\n    drop(s);\n}\n\
               fn w() {\n    let l = TcpListener::bind(\"10.0.0.1:0\")?;\n    \
               let p = l.local_addr()?;\n    drop(l);\n}\n";
    assert_eq!(released_port_sites(src)?, Vec::<usize>::new());
    Ok(())
}

/// The gate itself: no file under `tests/` reserves a port and releases it.
#[test]
fn no_test_reserves_a_port_and_releases_it() -> Result<(), TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files = Vec::new();
    rust_files(&root, &mut files)?;
    files.sort();
    assert!(
        files.len() > 100,
        "the scan read only {} files under {}",
        files.len(),
        root.display()
    );
    let mut found = Vec::new();
    // This file's own fixtures are planted occurrences.
    let this = root.join("released_port_scan_test.rs");
    for file in files.iter().filter(|f| **f != this) {
        let src = std::fs::read_to_string(file)?;
        for line in released_port_sites(&src)? {
            found.push(format!("{}:{line}", file.display()));
        }
    }
    assert!(
        found.is_empty(),
        "these tests release a port and then use its number, so a parallel \
         test can take it; hold one with support/ports.rs::refused_tcp_port \
         instead:\n{}",
        found.join("\n")
    );
    Ok(())
}
