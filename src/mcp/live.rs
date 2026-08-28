// SPDX-License-Identifier: MIT OR Apache-2.0

//! The live views of the loaded capture, served as MCP resources.
//!
//! `sipnab://reference/...` is documentation compiled into the binary and
//! `sipnab:///<file>` is a file on disk. Neither can change while a run is
//! answering questions, so neither is worth subscribing to. These are the URIs
//! that DO change, because sipnab is watching traffic while the client reads:
//!
//! | URI | What it holds |
//! |---|---|
//! | `sipnab://live/dialogs` | every dialog the capture currently holds |
//! | `sipnab://live/dialogs/<Call-ID>` | one dialog, by Call-ID |
//!
//! They exist for two reasons that arrived together. `resources/subscribe`
//! needs something whose content genuinely moves, and `completion/complete`
//! needs a resource TEMPLATE to hang a variable off — the MCP completion
//! primitive completes prompt arguments and resource-template variables, and
//! nothing else. `sipnab://live/dialogs/{call_id}` is both: the thing a client
//! subscribes to, and the thing whose `call_id` is completed from the capture.
//!
//! # These are views, not a second analysis
//!
//! A read renders the same `DialogPage` `list_dialogs` returns, through the
//! same `dialog_page` helper, under the same `--mcp-max-rows` ceiling and the
//! same untrusted-text fencing. The resource door and the tool door must
//! answer identically or an operator has two versions of the capture to
//! reconcile.

/// Every dialog the loaded capture holds.
pub const DIALOG_LIST_URI: &str = "sipnab://live/dialogs";

/// One dialog, by Call-ID. Everything after this prefix IS the Call-ID.
pub const DIALOG_URI_PREFIX: &str = "sipnab://live/dialogs/";

/// A live view of the loaded capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Live {
    /// The whole dialog list, bounded by `--mcp-max-rows`.
    DialogList,
    /// One dialog, named by its Call-ID.
    Dialog(
        /// The Call-ID, taken verbatim from the URI.
        String,
    ),
}

impl Live {
    /// Which live view `uri` names, or `None` when it names none.
    ///
    /// The Call-ID is taken VERBATIM from the tail of the URI: no
    /// percent-decoding, no splitting on `/`. A Call-ID is opaque to sipnab
    /// everywhere else, and a decoder here would be a second place where two
    /// different strings could resolve to one dialog.
    #[must_use]
    pub fn parse(uri: &str) -> Option<Self> {
        if uri == DIALOG_LIST_URI {
            return Some(Self::DialogList);
        }
        let call_id = uri.strip_prefix(DIALOG_URI_PREFIX)?;
        // A trailing slash and nothing else is the list URI written oddly, not
        // a dialog whose Call-ID is empty. No dialog has an empty Call-ID, so
        // resolving it to one would be a read that can never succeed.
        if call_id.is_empty() {
            return None;
        }
        Some(Self::Dialog(call_id.to_string()))
    }

    /// The URI this view is read back by.
    #[must_use]
    pub fn uri(&self) -> String {
        match self {
            Self::DialogList => DIALOG_LIST_URI.to_string(),
            Self::Dialog(call_id) => format!("{DIALOG_URI_PREFIX}{call_id}"),
        }
    }

    /// Short name shown in a resource listing.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::DialogList => "Live dialog list",
            Self::Dialog(_) => "Live dialog",
        }
    }
}

/// The live resources a client sees in `resources/list`.
///
/// Only the list. A per-Call-ID URI is a template rather than an entry:
/// enumerating one resource per dialog would put the whole capture in a
/// listing that exists so a client can choose what to read.
#[must_use]
pub fn listed() -> Vec<Live> {
    vec![Live::DialogList]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list URI resolves to the list.
    #[test]
    fn the_list_uri_parses() {
        assert_eq!(Live::parse(DIALOG_LIST_URI), Some(Live::DialogList));
    }

    /// A Call-ID URI resolves to that Call-ID, verbatim.
    #[test]
    fn a_dialog_uri_carries_its_call_id_unchanged() {
        assert_eq!(
            Live::parse("sipnab://live/dialogs/abc123@10.0.0.1"),
            Some(Live::Dialog("abc123@10.0.0.1".to_string()))
        );
    }

    /// A Call-ID containing a slash is still one Call-ID.
    ///
    /// Splitting on `/` would silently truncate it and read a different
    /// dialog, or none, while reporting success.
    #[test]
    fn a_call_id_containing_a_slash_is_not_split() {
        assert_eq!(
            Live::parse("sipnab://live/dialogs/a/b"),
            Some(Live::Dialog("a/b".to_string()))
        );
    }

    /// A URI naming no live view resolves to nothing.
    #[test]
    fn an_unrelated_uri_is_not_a_live_view() {
        for uri in [
            "sipnab://reference/filter-dsl",
            "sipnab:///capture.pcap",
            "sipnab://live/streams",
            "sipnab://live/dialogs/",
            "https://sipnab.com",
        ] {
            assert!(
                Live::parse(uri).is_none(),
                "{uri} must not resolve to a live view"
            );
        }
    }

    /// Parsing a rendered URI yields the view it was rendered from.
    #[test]
    fn a_view_round_trips_through_its_uri() {
        for view in [
            Live::DialogList,
            Live::Dialog("call-1@host".to_string()),
            Live::Dialog("a/b".to_string()),
        ] {
            assert_eq!(Live::parse(&view.uri()), Some(view.clone()), "{view:?}");
        }
    }

    /// The listing holds the list and not one entry per dialog.
    #[test]
    fn only_the_dialog_list_is_listed() {
        assert_eq!(listed(), vec![Live::DialogList]);
    }
}
