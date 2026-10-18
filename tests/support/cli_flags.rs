// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The CLI flags clap cannot show a test, because a Cargo feature left them out.

/// Flags that exist only under a non-default Cargo feature.
///
/// A gate that enumerates the CLI through `sipnab::cli::Cli::command()` sees
/// the CLI clap actually built, so a `#[cfg(feature = ...)]` flag is absent
/// whenever the suite runs without that feature, while the docs, which
/// describe the whole program, still name it. The reduced-feature CI matrix
/// hits exactly that: `--plugin` is real under `plugins` and invisible under
/// `native,hep,api,mcp,mcp-http`.
///
/// Listed rather than inferred, so adding a feature-gated flag is a deliberate
/// entry here and not something a reader has to discover from a red matrix
/// job. Every gate that enumerates flags reads this one list.
pub const FEATURE_GATED: &[&str] = &["plugin"];
