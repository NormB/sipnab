// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where the MCP tool reference lives: an index page, and one page per
//! built-in bundle.
//!
//! The reference was one page of about 6,700 lines. It is now
//! `docs/mcp-tools.md`, which says what a bundle is and finds any tool by
//! name, plus `docs/mcp-tools-<bundle>.md` for each bundle in
//! [`sipnab::mcp_profile::BUNDLES`]. The page list is derived from that table,
//! never typed out, so a bundle added in code is a page every documentation
//! gate reads without being told about it.
//!
//! Consumers include it with `#[path = "support/mcp_reference.rs"] mod
//! mcp_reference;`. It lives under `tests/` so cargo does not build it as its
//! own test binary.

#![allow(dead_code)]

use std::path::Path;

/// The index page: what a bundle is, the bundle table, the alphabetical tool
/// lookup, and the rules every tool shares.
pub const INDEX: &str = "docs/mcp-tools.md";

/// The repo-relative path of the page documenting one built-in bundle.
#[must_use]
pub fn bundle_page(bundle: &str) -> String {
    format!("docs/mcp-tools-{bundle}.md")
}

/// The file name of a bundle's page, as a link from the index writes it.
#[must_use]
pub fn bundle_file(bundle: &str) -> String {
    format!("mcp-tools-{bundle}.md")
}

/// Every page of the reference, index first, then the bundles in the order
/// `BUNDLES` lists them.
#[must_use]
pub fn pages() -> Vec<String> {
    std::iter::once(INDEX.to_string())
        .chain(
            sipnab::mcp_profile::BUNDLES
                .iter()
                .map(|(bundle, _)| bundle_page(bundle)),
        )
        .collect()
}

/// Every page of the reference with its text, read from under `root`.
///
/// # Errors
///
/// Names the page that could not be read.
pub fn read_pages(root: &Path) -> Result<Vec<(String, String)>, String> {
    pages()
        .into_iter()
        .map(|rel| {
            std::fs::read_to_string(root.join(&rel))
                .map(|text| (rel.clone(), text))
                .map_err(|e| format!("{rel} is readable: {e}"))
        })
        .collect()
}

/// The whole reference as one string, pages joined in [`pages`] order.
///
/// # Errors
///
/// Names the page that could not be read.
pub fn read_all(root: &Path) -> Result<String, String> {
    Ok(read_pages(root)?
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join("\n"))
}
