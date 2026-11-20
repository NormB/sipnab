// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The F7 dialog's field help: the Filter DSL's field names, comparison
//! operators and combining words, which `F1` shows in the dialog.
//!
//! Every word comes from the parser's own lists
//! ([`crate::sip::dsl::FIELD_NAMES`], [`crate::sip::dsl::operator_tokens`],
//! [`crate::sip::dsl::LOGICAL_KEYWORDS`]), so the help cannot name a field or
//! an operator the language does not have, or leave one out.

/// The field help as lines of at most `width` columns.
///
/// Three groups, each starting on a line of its own: `Fields:` with every
/// field name and the `header.<name>` family, `Operators:` with every
/// comparison operator, and `Combine:` with `AND`, `OR`, `NOT` and the
/// parentheses. A group's words wrap at whole words; a word wider than
/// `width` is cut to `width`.
///
/// # Returns
/// The lines, or none for a `width` of 0.
pub(in crate::tui) fn field_help_lines(width: usize) -> Vec<String> {
    use crate::sip::dsl::{FIELD_NAMES, HEADER_FIELD_HINT, LOGICAL_KEYWORDS, operator_tokens};
    if width == 0 {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let fields = FIELD_NAMES.iter().copied().chain([HEADER_FIELD_HINT]);
    wrap_group(&mut lines, "Fields:", fields, width);
    wrap_group(&mut lines, "Operators:", operator_tokens(), width);
    let combine = LOGICAL_KEYWORDS.iter().copied().chain(["(", ")"]);
    wrap_group(&mut lines, "Combine:", combine, width);
    lines
}

/// Append `label` and `words` to `lines`, filling each line with as many
/// whole words as fit in `width` columns, one space apart. A word wider than
/// `width` is cut to it.
fn wrap_group<'a>(
    lines: &mut Vec<String>,
    label: &'a str,
    words: impl IntoIterator<Item = &'a str>,
    width: usize,
) {
    let mut line = String::new();
    let mut used = 0;
    for word in std::iter::once(label).chain(words) {
        let word: String = word.chars().take(width).collect();
        let len = word.chars().count();
        if used == 0 {
            line = word;
            used = len;
        } else if used + 1 + len <= width {
            line.push(' ');
            line.push_str(&word);
            used += 1 + len;
        } else {
            lines.push(std::mem::replace(&mut line, word));
            used = len;
        }
    }
    if used > 0 {
        lines.push(line);
    }
}

/// Unit tests for the field help: complete against the parser's lists, and
/// inside its width.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::dsl::{FIELD_NAMES, HEADER_FIELD_HINT, LOGICAL_KEYWORDS, operator_tokens};

    /// The words of every line, split at spaces, with the group labels.
    fn words(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .flat_map(|l| l.split(' ').filter(|w| !w.is_empty()).map(str::to_owned))
            .collect()
    }

    /// The line that starts group `label`, and the lines after it up to the
    /// next group.
    fn group(lines: &[String], label: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut inside = false;
        for line in lines {
            let starts_group = ["Fields:", "Operators:", "Combine:"]
                .iter()
                .any(|g| line.starts_with(g));
            if starts_group {
                inside = line.starts_with(label);
            }
            if inside {
                out.push(line.clone());
            }
        }
        out
    }

    /// Every field the parser knows is in the Fields group, as a whole word.
    #[test]
    fn every_field_name_is_listed() {
        let lines = field_help_lines(72);
        let listed = words(&group(&lines, "Fields:"));
        for name in FIELD_NAMES {
            assert!(
                listed.iter().any(|w| w == name),
                "field '{name}' is missing from the help: {lines:?}"
            );
        }
    }

    /// The header family is listed as `header.<name>`.
    #[test]
    fn the_header_family_is_listed() {
        let lines = field_help_lines(72);
        assert!(
            words(&group(&lines, "Fields:")).contains(&HEADER_FIELD_HINT.to_owned()),
            "header.<name> is missing: {lines:?}"
        );
    }

    /// Every operator the parser takes is in the Operators group.
    #[test]
    fn every_operator_is_listed() {
        let lines = field_help_lines(72);
        let listed = words(&group(&lines, "Operators:"));
        let mut count = 0;
        for token in operator_tokens() {
            count += 1;
            assert!(
                listed.iter().any(|w| w == token),
                "operator '{token}' is missing: {lines:?}"
            );
        }
        assert_eq!(count, 8, "the parser has eight operators");
    }

    /// AND, OR, NOT and the parentheses are in the Combine group.
    #[test]
    fn the_combining_words_are_listed() {
        let lines = field_help_lines(72);
        let listed = words(&group(&lines, "Combine:"));
        for word in LOGICAL_KEYWORDS.iter().copied().chain(["(", ")"]) {
            assert!(
                listed.iter().any(|w| w == word),
                "'{word}' is missing: {lines:?}"
            );
        }
    }

    /// No word appears in the help that is not a field, an operator, a
    /// combining word or a label: the help names nothing the language lacks.
    #[test]
    fn the_help_names_nothing_else() {
        let lines = field_help_lines(72);
        let ops: Vec<&str> = operator_tokens().collect();
        for word in words(&lines) {
            let known = FIELD_NAMES.contains(&word.as_str())
                || word == HEADER_FIELD_HINT
                || ops.contains(&word.as_str())
                || LOGICAL_KEYWORDS.contains(&word.as_str())
                || ["(", ")", "Fields:", "Operators:", "Combine:"].contains(&word.as_str());
            assert!(known, "'{word}' is not part of the language: {lines:?}");
        }
    }

    /// Each group starts on a line of its own, in the order Fields,
    /// Operators, Combine.
    #[test]
    fn the_groups_start_lines_in_order() {
        let lines = field_help_lines(72);
        let starts: Vec<usize> = ["Fields:", "Operators:", "Combine:"]
            .iter()
            .filter_map(|g| lines.iter().position(|l| l.starts_with(g)))
            .collect();
        assert_eq!(starts.len(), 3, "all three groups: {lines:?}");
        assert!(
            starts[0] < starts[1] && starts[1] < starts[2],
            "in order: {starts:?}"
        );
    }

    /// At the dialog's width the help fits the ten rows the dialog gives it.
    #[test]
    fn the_help_fits_the_dialog_at_its_width() {
        let lines = field_help_lines(72);
        assert!(!lines.is_empty(), "there is help to show");
        assert!(
            lines.len() <= 9,
            "{} lines do not fit: {lines:?}",
            lines.len()
        );
    }

    /// No line is wider than asked, at any width.
    #[test]
    fn no_line_is_wider_than_asked() {
        for width in 1..=100 {
            for line in field_help_lines(width) {
                assert!(
                    line.chars().count() <= width,
                    "width {width}: {line:?} is {} wide",
                    line.chars().count()
                );
            }
        }
    }

    /// A width of zero yields no lines rather than empty or broken ones.
    #[test]
    fn a_zero_width_yields_no_lines() {
        assert_eq!(
            field_help_lines(0),
            Vec::<String>::new(),
            "no room, no lines"
        );
    }

    /// A word wider than the width is cut to it, not dropped.
    #[test]
    fn a_word_wider_than_the_width_is_cut() {
        let lines = field_help_lines(5);
        assert!(
            lines.iter().any(|l| l == "durat"),
            "duration_asymmetry is cut to five columns: {lines:?}"
        );
    }

    /// The help at a narrow width still names every field, wrapped onto more
    /// lines, once the width holds the widest name.
    #[test]
    fn a_narrow_width_wraps_but_keeps_every_field() {
        let widest = FIELD_NAMES.iter().map(|f| f.len()).max().unwrap_or(0);
        let lines = field_help_lines(widest);
        let listed = words(&lines);
        for name in FIELD_NAMES {
            assert!(
                listed.iter().any(|w| w == name),
                "'{name}' lost at {widest}"
            );
        }
        assert!(
            lines.len() > field_help_lines(72).len(),
            "more lines when narrow"
        );
    }
}
