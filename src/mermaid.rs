// SPDX-License-Identifier: MIT OR Apache-2.0

//! Neutralizing capture-derived text for embedding in Mermaid source.
//!
//! # Why this module is ungated
//!
//! sipnab renders Mermaid from two places that cannot share a feature: the TUI
//! exporter under `feature = "tui"`, and the browser analyzer in
//! `crate::wasm`, which compiles only for `target_arch = "wasm32"` where
//! `native` is off. `crate::output` is gated on `native`, so it cannot hold a
//! rule the wasm build needs. That gap is not academic — it is why the escaping
//! fix reached one generator and not the other, and why `msg.reason`, the
//! reason phrase written by whoever sent the packet, was interpolated raw into
//! diagram source the website hands to the reader as a `.mmd` download.
//!
//! One rule, one module, reachable from every target.

/// Neutralize untrusted text for embedding in a Mermaid label or note.
///
/// # What it defends against
///
/// A label is sender-written: a SIP reason phrase, a `User-Agent`, an SDP
/// session name, a resolved PTR record. Mermaid's grammar gives several of
/// those characters meaning, so text that arrives from the wire can otherwise
/// end the statement and have what follows parsed as diagram syntax.
///
/// * `\n` and `\r` become spaces. A statement ends at the newline, so a label
///   carrying one splits into an arrow plus an attacker-chosen second line.
/// * `#` becomes `#35;`. It opens Mermaid's own numeric entity escapes, so an
///   unescaped one lets a label spell any character it likes.
/// * `;` becomes `#59;`, `<` becomes `#60;`, `>` becomes `#62;`. Removing raw
///   angle brackets also means the HTML wrapper the TUI writes can never
///   receive label-injected markup.
/// * `%` becomes `#37;`. `%%` introduces a Mermaid comment: the vendored
///   renderer's lexer carries `%%(?!\{)[^\n]+\n?` and message-text rules of the
///   form `%%)|[^\n\r]*)`, so a label containing `%%` truncates there. A
///   truncated label is a quiet wrong answer rather than a loud one, which is
///   the worse failure.
///
/// Every replacement is a Mermaid numeric entity, so the rendered diagram shows
/// the original glyph. The reader sees what the packet said; the parser does
/// not.
///
/// # Arguments
///
/// * `s` — capture-derived text.
///
/// # Returns
///
/// The same text with the characters above replaced. Non-special characters,
/// including every non-ASCII one, pass through unchanged.
#[must_use]
pub fn escape_mermaid_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\n' | '\r' => out.push(' '),
            '#' => out.push_str("#35;"),
            '%' => out.push_str("#37;"),
            ';' => out.push_str("#59;"),
            '<' => out.push_str("#60;"),
            '>' => out.push_str("#62;"),
            _ => out.push(ch),
        }
    }
    out
}

/// A Mermaid participant id derived from a position, not from an address.
///
/// # Why positional
///
/// The previous scheme mapped `.` and `:` to `_` in the address. That is
/// ambiguous for IPv6 — `fd00::1` and `fd00:0:0:1` collapse to the same id, so
/// two distinct endpoints silently merge into one lifeline — and it puts
/// capture-derived text where Mermaid expects an identifier. A positional id
/// cannot collide and cannot carry a payload; the address belongs in the `as`
/// label, where it is escaped like any other capture-derived text.
#[must_use]
pub fn participant_id(index: usize) -> String {
    format!("p{index}")
}

/// Edges the vendored renderer accepts before it refuses the diagram.
///
/// `website/static/js/mermaid.min.js` carries `maxEdges:500` and
/// `maxTextSize:5e4`. Past either it renders NOTHING — no partial picture, no
/// error a reader would connect to the cause — so a diagram that walks past
/// this is a blank panel, which is the worst way for an export to fail.
pub const RENDERER_MAX_EDGES: usize = 500;

/// Messages any sipnab-generated diagram will draw.
///
/// Below [`RENDERER_MAX_EDGES`] with room to spare: an arrow is one edge, but
/// a `Note` is another, and a diagram that only just fits is one feature away
/// from not fitting.
pub const MAX_MESSAGES: usize = 200;

// Asserted at compile time rather than in a test: both are constants, and a
// cap that drifted past the renderer's limit would produce blank exports on
// the one surface that actually renders them.
const _: () = assert!(
    MAX_MESSAGES < RENDERER_MAX_EDGES,
    "the message cap must leave the renderer room, or the export renders as \
     nothing at all"
);

/// A Mermaid `sequenceDiagram` for one dialog's messages.
///
/// # Why this lives here
///
/// The TUI has had a Mermaid exporter for some time and `render_ladder` — the
/// MCP tool named for a ladder — returned tables. An agent asking for a ladder
/// got a call report. This module is ungated, so the same generator serves the
/// agent surface, and the escaping rule is the one every target already shares.
///
/// # Bounds
///
/// The vendored renderer refuses a diagram over `maxEdges: 500` or
/// `maxTextSize: 50000` outright rather than degrading, so the output is
/// capped and says so **inside the diagram** — a truncated ladder that does not
/// admit it is a wrong picture rather than a partial one. Truncation lands on
/// a message boundary, never mid-exchange.
///
/// # Arguments
///
/// * `rows` — `(from, to, label, is_request)` per message, in capture order.
/// * `max_messages` — how many arrows to draw before truncating.
///
/// # Returns
///
/// Mermaid source. Participants are positional ids with the address carried
/// only in the label, so no capture-derived text reaches an identifier.
#[must_use]
pub fn sequence_diagram(rows: &[(String, String, String, bool)], max_messages: usize) -> String {
    let rows: Vec<DiagramRow> = rows
        .iter()
        .map(|(from, to, label, is_request)| DiagramRow {
            from: from.clone(),
            to: to.clone(),
            label: label.clone(),
            is_request: *is_request,
            note: None,
        })
        .collect();
    sequence_diagram_rows(&rows, &|endpoint| endpoint.to_string(), max_messages)
}

/// One message in a sequence diagram.
///
/// `note` carries what the ladder computed and the export used to throw away:
/// the timestamp offset, the post-dial delay, an SDP badge, a diagnosis. Those
/// annotations are the reason to draw the diagram at all — seven bare arrows
/// are a picture of the protocol, not of the call.
#[derive(Debug, Clone)]
pub struct DiagramRow {
    /// Sending endpoint identity.
    pub from: String,
    /// Receiving endpoint identity.
    pub to: String,
    /// The arrow's own label — a method, or a status line.
    pub label: String,
    /// Requests draw a solid arrow, responses a dashed one.
    pub is_request: bool,
    /// What the ladder knew about this message, if anything.
    pub note: Option<String>,
}

/// The full form: rows that may carry annotations, plus a label resolver.
///
/// # Arguments
/// * `rows` — messages in capture order.
/// * `label_for` — display name for an endpoint identity.
/// * `max_messages` — arrows to draw before truncating.
#[must_use]
pub fn sequence_diagram_rows(
    rows: &[DiagramRow],
    label_for: &dyn Fn(&str) -> String,
    max_messages: usize,
) -> String {
    let mut participants: Vec<&str> = Vec::new();
    for row in rows {
        for endpoint in [row.from.as_str(), row.to.as_str()] {
            if !participants.contains(&endpoint) {
                participants.push(endpoint);
            }
        }
    }

    let mut out = String::from(
        "sequenceDiagram
    autonumber
",
    );
    for (i, p) in participants.iter().enumerate() {
        // The id is positional and the address is escaped into the label: an
        // id cannot carry a payload, and an IPv6 address mangled into an
        // identifier can collide with a different one.
        out.push_str(&format!(
            "    participant {} as {}
",
            participant_id(i),
            escape_mermaid_label(&label_for(p))
        ));
    }
    out.push('\n');

    let index = |addr: &str| {
        participants
            .iter()
            .position(|p| *p == addr)
            .map_or_else(|| "p0".to_string(), participant_id)
    };

    for row in rows.iter().take(max_messages) {
        out.push_str(&format!(
            "    {}{}{}: {}
",
            index(&row.from),
            if row.is_request { "->>" } else { "-->>" },
            index(&row.to),
            escape_mermaid_label(&row.label)
        ));
        // What the ladder knew, attached to the arrow it belongs to. Without
        // this the export is seven bare arrows: a picture of the protocol
        // rather than of the call, and the annotations are the reason to draw
        // it at all.
        if let Some(note) = &row.note
            && !note.is_empty()
        {
            out.push_str(&format!(
                "    Note right of {}: {}
",
                index(&row.to),
                escape_mermaid_label(note)
            ));
        }
    }

    if rows.len() > max_messages {
        // In sipnab's own voice, and inside the diagram so it cannot be
        // separated from the picture it qualifies.
        out.push_str(&format!(
            "    Note over {},{}: sipnab: {} of {} messages shown (message cap)\n",
            participant_id(0),
            participant_id(participants.len().saturating_sub(1)),
            max_messages,
            rows.len()
        ));
    }
    out
}

/// The same diagram, with a caller-supplied display name per endpoint.
///
/// The TUI resolves an endpoint to a name (`--name-mode`, static or DNS) and
/// shows that instead of the bare address. Routing its export through the
/// address-only form would have silently dropped the operator's own name
/// resolution from every exported diagram — the identity stays the address,
/// because two endpoints can resolve to the same truncated name, and only the
/// LABEL changes.
///
/// # Arguments
///
/// * `rows` — `(from, to, label, is_request)` per message, in capture order.
///   `from`/`to` are identities, not display text.
/// * `label_for` — display name for an endpoint identity.
/// * `max_messages` — how many arrows to draw before truncating.
#[must_use]
pub fn sequence_diagram_with_labels(
    rows: &[(String, String, String, bool)],
    label_for: &dyn Fn(&str) -> String,
    max_messages: usize,
) -> String {
    let rows: Vec<DiagramRow> = rows
        .iter()
        .map(|(from, to, label, is_request)| DiagramRow {
            from: from.clone(),
            to: to.clone(),
            label: label.clone(),
            is_request: *is_request,
            note: None,
        })
        .collect();
    sequence_diagram_rows(&rows, label_for, max_messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reason phrase cannot end the statement it sits in.
    ///
    /// The defect this module exists for: `SIP/2.0 500 x\nNote over a,b: owned`
    /// as a reason phrase put an attacker-chosen Mermaid statement into the
    /// diagram.
    #[test]
    fn a_newline_cannot_split_a_label_into_a_second_statement() {
        let out = escape_mermaid_label("Busy\nNote over p0,p1: injected");
        assert!(!out.contains('\n'), "got {out:?}");
        assert!(out.starts_with("Busy Note"), "got {out:?}");
    }

    /// A carriage return is neutralized too.
    ///
    /// SIP is CRLF-framed, so a reason phrase that survives a lenient parse is
    /// far likelier to carry `\r` than `\n`. Handling only `\n` would leave the
    /// commoner case open.
    #[test]
    fn a_carriage_return_is_neutralized() {
        assert!(!escape_mermaid_label("Busy\r\nx").contains(['\r', '\n']));
    }

    /// `#` is escaped, or a label can spell any character through Mermaid's own
    /// entity syntax.
    #[test]
    fn the_entity_introducer_is_itself_escaped() {
        assert_eq!(escape_mermaid_label("#59;"), "#35;59#59;");
    }

    /// `%%` cannot truncate a label.
    ///
    /// The gap that survived the first fix. `%%` opens a Mermaid comment, so an
    /// unescaped one silently drops the rest of the label — and a silently
    /// shortened label is worse than a loud parse error, because nothing says
    /// the diagram is incomplete.
    #[test]
    fn a_comment_introducer_cannot_truncate_a_label() {
        let out = escape_mermaid_label("Busy %% here");
        assert!(!out.contains("%%"), "got {out:?}");
        assert!(out.ends_with("here"), "the tail must survive: {out:?}");
    }

    /// Angle brackets never reach the HTML wrapper.
    ///
    /// The TUI writes the diagram into a `<pre>` inside a generated page, so a
    /// label carrying markup is an injection into that page as well as into the
    /// diagram.
    #[test]
    fn angle_brackets_cannot_reach_the_html_wrapper() {
        let out = escape_mermaid_label("<script>alert(1)</script>");
        assert!(!out.contains('<') && !out.contains('>'), "got {out:?}");
    }

    /// A semicolon becomes an entity rather than a statement terminator.
    ///
    /// Asserted as the exact output, not as "contains no `;`": the entity
    /// `#59;` ends in a semicolon by construction, so the absence test can
    /// never pass and would have to be weakened into something vacuous. What
    /// matters is that no BARE semicolon survives.
    #[test]
    fn a_semicolon_becomes_an_entity() {
        assert_eq!(escape_mermaid_label("a;b"), "a#59;b");
    }

    /// No bare separator survives, stated as one property over every character
    /// the escaper claims to handle.
    ///
    /// The per-character tests above each pin one replacement. This one pins
    /// the invariant they exist to serve: after escaping, the only occurrences
    /// of a special character are the ones that close an entity sipnab wrote.
    #[test]
    fn every_special_character_leaves_only_entities_behind() {
        let out = escape_mermaid_label("a<b>c#d%e;f");
        assert_eq!(out, "a#60;b#62;c#35;d#37;e#59;f");
        // Every `;` in the result closes a `#NN` entity — none is a bare one.
        let bare = out
            .match_indices(';')
            .filter(|(i, _)| !out[..*i].ends_with(|c: char| c.is_ascii_digit()))
            .count();
        assert_eq!(bare, 0, "a bare semicolon survived: {out:?}");
    }

    /// Ordinary text is unchanged, including non-ASCII.
    ///
    /// The negative case for the escaper itself: over-escaping would corrupt
    /// every reason phrase in a non-English deployment, and nothing else would
    /// report it.
    #[test]
    fn ordinary_text_passes_through_untouched() {
        for s in [
            "Busy Here",
            "Service Unavailable",
            "Занято",
            "話中",
            "occupé",
        ] {
            assert_eq!(escape_mermaid_label(s), s, "{s} must survive unchanged");
        }
    }

    /// The empty string survives.
    #[test]
    fn the_empty_string_is_empty() {
        assert_eq!(escape_mermaid_label(""), "");
    }

    /// Participant ids are positional and cannot collide.
    ///
    /// Two IPv6 endpoints that differ only in zero-compression produced the
    /// same id under the address-mangling scheme, silently merging two
    /// lifelines. A positional id cannot.
    #[test]
    fn participant_ids_are_distinct_by_construction() {
        let ids: Vec<String> = (0..4).map(participant_id).collect();
        assert_eq!(ids, ["p0", "p1", "p2", "p3"]);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "ids must be unique");
    }

    /// A participant id carries no capture-derived text at all.
    ///
    /// The structural half: an id that cannot contain a payload needs no
    /// escaping and cannot be got wrong by a future caller.
    #[test]
    fn a_participant_id_is_alphanumeric() {
        assert!(
            participant_id(17)
                .chars()
                .all(|c| c.is_ascii_alphanumeric()),
            "got {}",
            participant_id(17)
        );
    }
    /// The shared builder escapes every label it writes.
    ///
    /// The substance behind the source gate in
    /// `tests/mermaid_one_escaper_test.rs`. Both Mermaid generators delegate
    /// here rather than escaping themselves, so this is now the ONE place the
    /// escaping actually happens — for the arrow labels and for the
    /// participant names alike, both of which can be capture-derived.
    #[test]
    fn the_shared_builder_escapes_every_label_it_writes() {
        // `#` starts a Mermaid entity, `;` and a newline end a statement, and
        // `<`/`>` matter to the HTML wrapper the TUI writes around this.
        let nasty = "BAD#;<b>\nsecond line";
        let rows = vec![(
            "198.51.100.1:5060".to_string(),
            "198.51.100.2:5060".to_string(),
            nasty.to_string(),
            true,
        )];

        let out = sequence_diagram(&rows, MAX_MESSAGES);
        assert!(
            !out.contains("BAD#;"),
            "the raw message label reached the diagram: {out}"
        );
        assert!(
            out.lines().filter(|l| l.contains("->>")).count() == 1,
            "an unescaped newline split one arrow into two statements: {out}"
        );

        // And the participant label, which a resolver can supply.
        let labeled = sequence_diagram_with_labels(&rows, &|_| nasty.to_string(), MAX_MESSAGES);
        assert!(
            !labeled.contains("BAD#;"),
            "the raw participant label reached the diagram: {labeled}"
        );
        assert_eq!(
            labeled
                .lines()
                .filter(|l| l.trim_start().starts_with("participant "))
                .count(),
            2,
            "an unescaped newline in a participant label added a statement: \
             {labeled}"
        );
    }

    /// A caller-supplied label changes the display name and nothing else.
    ///
    /// The identity stays the endpoint string: two endpoints that resolve to
    /// the same name are still two lifelines, because collapsing them would
    /// merge two hosts into one row of the ladder.
    #[test]
    fn a_shared_label_does_not_merge_two_endpoints() {
        let rows = vec![(
            "198.51.100.1:5060".to_string(),
            "198.51.100.2:5060".to_string(),
            "INVITE".to_string(),
            true,
        )];
        let out = sequence_diagram_with_labels(&rows, &|_| "same-name".to_string(), MAX_MESSAGES);
        assert_eq!(
            out.lines()
                .filter(|l| l.trim_start().starts_with("participant "))
                .count(),
            2,
            "two endpoints sharing a resolved name are still two lifelines: \
             {out}"
        );
    }
}
