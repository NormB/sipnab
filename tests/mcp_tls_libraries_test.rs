// SPDX-License-Identifier: MIT OR Apache-2.0

//! `list_tls_libraries`: what an agent is told about reading TLS without keys.
//!
//! The property these hold to is not "the list is right" — that depends on the
//! machine. It is that **an agent cannot mistake "this server cannot see it"
//! for "this host does not use TLS"**. Those two produce the same empty list
//! and lead to opposite conclusions, so every field that separates them is
//! required to be present and to say so in prose the agent will relay.

#![cfg(feature = "mcp")]

use sipnab::mcp::server::{TlsLibraryEntry, build_tls_libraries_response, tls_libraries_response};

/// A reachable entry, for the branches that need one.
fn reachable(flavour: &str, symbol: &str, inode: u64) -> TlsLibraryEntry {
    TlsLibraryEntry {
        flavour: flavour.to_string(),
        path: "/usr/lib/libssl.so.3".to_string(),
        inode,
        process_count: 3,
        symbol: symbol.to_string(),
        probe_path: Some("/proc/1/root/usr/lib/libssl.so.3".to_string()),
    }
}

/// **The branch this tool exists to get right.** An empty list means one of
/// two opposite things, and only `privileged` separates them — so the prose an
/// agent relays has to separate them too.
#[test]
fn an_empty_list_reads_differently_depending_on_privilege() {
    let unprivileged = build_tls_libraries_response(true, false, Vec::new());
    assert!(
        unprivileged.summary.contains("unprivileged")
            && unprivileged.summary.contains("root")
            && unprivileged.summary.contains("before concluding"),
        "an empty list from an unprivileged server must say the list is not \
         evidence about the host: {}",
        unprivileged.summary
    );

    let as_root = build_tls_libraries_response(true, true, Vec::new());
    assert!(
        as_root.summary.contains("would need keys"),
        "as root, an empty list IS evidence, and the agent should be told the \
         conclusion it licenses: {}",
        as_root.summary
    );
    assert_ne!(
        unprivileged.summary, as_root.summary,
        "the same sentence for both is exactly the failure this guards"
    );
}

/// A partial capture must never be described as a whole one.
#[test]
fn an_unreachable_library_is_stated_in_the_prose_not_only_in_a_count() {
    let mut hidden = reachable("wolfSSL", "wolfSSL_write", 99);
    hidden.probe_path = None;
    let r = build_tls_libraries_response(
        true,
        true,
        vec![reachable("OpenSSL", "SSL_write", 21143), hidden],
    );
    assert_eq!(r.unreachable_count, 1);
    assert!(
        r.summary.contains("1 of 2") && r.summary.contains("would be missed"),
        "traffic that will be absent from the capture must be in the sentence \
         the agent relays, not only in a field it may not read: {}",
        r.summary
    );
}

/// With everything reachable there is no missing-traffic caveat to make.
#[test]
fn a_complete_capture_is_not_hedged() {
    let r = build_tls_libraries_response(true, true, vec![reachable("OpenSSL", "SSL_write", 1)]);
    assert_eq!(r.unreachable_count, 0);
    assert!(r.summary.contains("1 of 1 TLS library"), "{}", r.summary);
    assert!(
        !r.summary.contains("missed"),
        "nothing is missing, so nothing should suggest it is: {}",
        r.summary
    );
}

/// Live call: whatever this machine has, the invariants hold.
#[test]
fn the_live_response_is_well_formed() {
    let r = tls_libraries_response();
    assert_eq!(r.schema_version, 1);
    assert!(
        !r.summary.is_empty(),
        "a caller relays the summary; an empty one loses the caveat entirely"
    );
}

/// A library that is in use but cannot be probed is a gap in the capture, and
/// the count must agree with the entries rather than being reported separately.
#[test]
fn the_unreachable_count_matches_the_entries_it_summarises() {
    let r = tls_libraries_response();
    let actual = r
        .libraries
        .iter()
        .filter(|l| l.probe_path.is_none())
        .count();
    assert_eq!(
        r.unreachable_count, actual,
        "a count that disagrees with the list is worse than no count: it is the \
         number an agent will quote"
    );
    if r.unreachable_count > 0 {
        assert!(
            r.summary.contains("missed") || r.summary.contains("cannot be reached"),
            "traffic that will be missing from the capture must be stated: {}",
            r.summary
        );
    }
}

/// Every entry must carry the symbol its flavour exports. A wrong pairing here
/// would have an agent report a probe target that cannot resolve.
#[test]
fn every_entry_pairs_its_flavour_with_the_symbol_that_flavour_exports() {
    for lib in tls_libraries_response().libraries {
        let expected = match lib.flavour.as_str() {
            "OpenSSL" => "SSL_write",
            "wolfSSL" => "wolfSSL_write",
            other => panic!("unexpected flavour {other}: sipnab probes only these two"),
        };
        assert_eq!(lib.symbol, expected, "for {}", lib.path);
        assert!(!lib.path.is_empty());
        assert!(
            lib.process_count > 0,
            "a library is reported only because a process maps it"
        );
    }
}

/// Off Linux, or without `native`, the answer is "cannot", not "none found".
#[test]
fn an_unsupported_build_says_so_rather_than_reporting_nothing() {
    let r = tls_libraries_response();
    if !r.supported {
        assert!(r.libraries.is_empty());
        assert!(
            r.summary.contains("Linux") || r.summary.contains("native"),
            "an agent must learn WHY, not just that the list is empty: {}",
            r.summary
        );
    }
}

/// The identity field exists because the path is not unique. If an entry ever
/// carried inode 0 the agent would have no way to tell two libraries apart.
#[test]
fn every_entry_carries_the_inode_that_identifies_it() {
    for lib in tls_libraries_response().libraries {
        assert_ne!(
            lib.inode, 0,
            "inode 0 is an anonymous mapping and cannot name a file: {}",
            lib.path
        );
    }
}
