// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A name the terminal UI saves with `F2` (to the config file, or for the
//! session only) is published to the process's live `[filters]` table, and
//! every filter compiled after that resolves it: the REST API's
//! `compile_query_filter` and the MCP server's `compile_filter` both compile
//! through `sipnab::sip::dsl::parse_filter`, which reads that table.
//!
//! The process's table is global, so this binary holds ONE test that walks
//! the whole sequence: a second test in the same process would race it. The
//! REST and MCP routes themselves are not driven here: no public entry
//! point starts them beside a terminal UI in one process, so the shared
//! conversion they call is what is tested.

use std::collections::BTreeMap;

use sipnab::sip::dsl::{AliasThresholds, parse_filter, resolve_filter_text};
use sipnab::sip::named_filters::{NamedFilters, install, installed, publish};

type TestError = Box<dyn std::error::Error>;

/// `pairs` resolved as a `[filters]` table.
fn table(pairs: &[(&str, &str)]) -> Result<NamedFilters, TestError> {
    let defs: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    Ok(NamedFilters::resolve(&defs, &AliasThresholds::default())?)
}

/// Startup table, a publish, and what every later compile sees.
#[test]
fn a_published_name_is_resolved_by_every_later_compile() -> Result<(), TestError> {
    let t = AliasThresholds::default();
    assert!(
        install(table(&[("big", "msg_count > 5")])?),
        "startup install"
    );

    // Before the save: the name is unknown, and the message says which
    // names the run defines.
    let before = parse_filter("@large", &t)
        .err()
        .ok_or("@large must be unknown before the save")?
        .to_string();
    assert!(before.contains("large"), "names the reference: {before}");
    assert!(before.contains("big"), "lists the run's names: {before}");

    // The save publishes the run's new table.
    publish(installed().with_added("large", "msg_count > 9", &t)?);

    assert!(
        parse_filter("@large", &t).is_ok(),
        "@large compiles after the publish"
    );
    assert!(
        parse_filter("@large AND @big", &t).is_ok(),
        "the new name beside a startup name"
    );
    assert_eq!(
        resolve_filter_text("@large", &t),
        "(msg_count > 9)",
        "expanded to its definition"
    );
    assert_eq!(
        installed().names().collect::<Vec<_>>(),
        ["big", "large"],
        "the live table holds both"
    );

    // A second startup install cannot replace the live table.
    assert!(
        !install(table(&[("other", "msg_count > 1")])?),
        "install after start is refused"
    );
    assert!(
        parse_filter("@large", &t).is_ok(),
        "the published name survives a late install"
    );
    Ok(())
}
