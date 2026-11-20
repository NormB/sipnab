// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The filter a REST or MCP request asks for, and why a request is refused.
//!
//! A request names its filter in one of two ways. `filter` carries an
//! expression or a diagnostic alias name, in which each `@name` stands for a
//! `[filters]` entry. `named` carries the name of one `[filters]` entry or one
//! built-in alias, with nothing else around it. The two are alternatives: a
//! request that gives both is refused, because it names two filters and does
//! not say which one applies.
//!
//! [`compile_request`] is the one rule both surfaces apply, so a REST route
//! and an MCP tool accept and refuse the same requests with the same words.
//! [`check_expression`] is the compile step on its own, which the validation
//! route and tool call to report the parser's message and position.
//!
//! The `[filters]` table is an argument everywhere here, so every function
//! can be driven with any table. The surfaces pass the run's live table as
//! it is when the request arrives ([`super::named_filters::installed`]): the
//! startup table, plus each name the terminal UI saved since.

use super::dsl::{AliasThresholds, DIAGNOSTIC_ALIASES, FilterExpr};
use super::named_filters::NamedFilters;

/// Why an expression did not compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRejection {
    /// The parser's message, the text every surface has printed for this
    /// expression: for a syntax error, the headline, the expression, a caret
    /// line, the operator list and the docs pointer.
    pub message: String,
    /// Where the parser stopped: the 0-based character column in the
    /// expression with its leading and trailing whitespace removed, the
    /// number the message's headline prints after `at position`.
    ///
    /// `None` when the parser names no place (an empty expression, an
    /// undefined `@name`, a depth or size limit), and when the text the parser
    /// read is an expansion (of an alias or of an `@name`) rather than the
    /// expression as sent, because a column in the expansion is not a column
    /// in the caller's text.
    pub position: Option<usize>,
}

/// Which request parameter a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterParam {
    /// The `filter` parameter: an expression or alias name.
    Filter,
    /// The `named` parameter: the name of one filter.
    Named,
}

impl FilterParam {
    /// The parameter's name as a request spells it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Filter => "filter",
            Self::Named => "named",
        }
    }
}

/// Why a request's `filter` and `named` parameters select no filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterRequestError {
    /// Both `filter` and `named` were given.
    Conflict,
    /// `named` was given with no name in it.
    EmptyName,
    /// `named` names no `[filters]` entry and no built-in alias.
    UnknownName {
        /// The name as asked for, without a leading `@`.
        name: String,
        /// What sipnab says about an undefined name, which lists the names
        /// that are defined.
        message: String,
    },
    /// The expression did not compile.
    Invalid {
        /// The parameter that carried it.
        param: FilterParam,
        /// The parser's message and position.
        rejection: FilterRejection,
    },
}

impl FilterRequestError {
    /// The parameter this refusal is about, or `None` for a conflict between
    /// the two.
    #[must_use]
    pub fn param(&self) -> Option<FilterParam> {
        match self {
            Self::Conflict => None,
            Self::EmptyName | Self::UnknownName { .. } => Some(FilterParam::Named),
            Self::Invalid { param, .. } => Some(*param),
        }
    }
}

impl std::fmt::Display for FilterRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => f.write_str(CONFLICT_MESSAGE),
            Self::EmptyName => f.write_str(EMPTY_NAME_MESSAGE),
            Self::UnknownName { message, .. } => f.write_str(message),
            Self::Invalid { rejection, .. } => f.write_str(&rejection.message),
        }
    }
}

impl std::error::Error for FilterRequestError {}

/// The refusal for a request that gives both `filter` and `named`.
pub const CONFLICT_MESSAGE: &str = "`filter` and `named` are alternatives, not a pair: \
     `filter` is an expression and `named` is the name of one filter. Give one, \
     or write the name into the expression as `@name`";

/// The refusal for a `named` parameter with no name in it.
pub const EMPTY_NAME_MESSAGE: &str = "`named` is empty; give the name of a [filters] \
     entry or a built-in alias";

/// Compile `input` the way every `filter` parameter is compiled, keeping the
/// parser's position.
///
/// `@name` references resolve through `filters`; a diagnostic alias name
/// expands with `t`. The expression and the message are the ones
/// [`super::dsl::parse_filter`] gives when `filters` is the installed table.
///
/// # Errors
///
/// A [`FilterRejection`] with the parser's message, and its position when
/// the parser read the expression as sent.
pub fn check_expression(
    input: &str,
    filters: &NamedFilters,
    t: &AliasThresholds,
) -> Result<FilterExpr, FilterRejection> {
    let resolved =
        super::dsl::resolve_typed_filter(input, filters, t).map_err(|message| FilterRejection {
            message,
            position: None,
        })?;
    FilterExpr::parse(&resolved).map_err(|e| {
        // The parser's offset is a byte offset into the text it read, trimmed.
        // It is a place in the caller's text only when nothing was expanded.
        let read = resolved.trim();
        let position = e
            .downcast_ref::<super::dsl::SyntaxError>()
            .filter(|_| resolved == input)
            .and_then(|s| read.get(..s.offset()))
            .map(|before| before.chars().count());
        FilterRejection {
            message: e.to_string(),
            position,
        }
    })
}

/// The expression `named` stands for: the expansion of the `[filters]` entry
/// of that name, or of the built-in alias of that name. A leading `@` is
/// accepted, so `@sales` and `sales` name the same filter.
///
/// # Errors
///
/// [`FilterRequestError::EmptyName`] for an empty name, and
/// [`FilterRequestError::UnknownName`] for a name nothing defines.
pub fn named_expansion(
    named: &str,
    filters: &NamedFilters,
    t: &AliasThresholds,
) -> Result<String, FilterRequestError> {
    let name = named.strip_prefix('@').unwrap_or(named);
    if name.is_empty() {
        return Err(FilterRequestError::EmptyName);
    }
    filters
        .expansion(name)
        .map(str::to_owned)
        .or_else(|| super::dsl::expand_alias(name, t))
        .ok_or_else(|| FilterRequestError::UnknownName {
            name: name.to_owned(),
            message: super::named_filters::unknown_reference_message(name, filters),
        })
}

/// Compile a request's `filter` and `named` parameters into the filter it
/// asks for, or `None` when it gives neither.
///
/// # Errors
///
/// [`FilterRequestError::Conflict`] when both are given; the
/// [`named_expansion`] refusals for `named`; and
/// [`FilterRequestError::Invalid`] when the expression does not compile.
pub fn compile_request(
    filter: Option<&str>,
    named: Option<&str>,
    filters: &NamedFilters,
    t: &AliasThresholds,
) -> Result<Option<FilterExpr>, FilterRequestError> {
    let (param, text) = match (filter, named) {
        (Some(_), Some(_)) => return Err(FilterRequestError::Conflict),
        (None, None) => return Ok(None),
        (Some(f), None) => (FilterParam::Filter, f.to_owned()),
        (None, Some(n)) => (FilterParam::Named, named_expansion(n, filters, t)?),
    };
    check_expression(&text, filters, t)
        .map(Some)
        .map_err(|rejection| FilterRequestError::Invalid { param, rejection })
}

/// Every name `named` accepts: the `[filters]` names in order, then the
/// built-in aliases.
#[must_use]
pub fn accepted_names(filters: &NamedFilters) -> Vec<String> {
    filters
        .names()
        .chain(DIAGNOSTIC_ALIASES)
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// The shipped alias thresholds.
    fn t() -> AliasThresholds {
        AliasThresholds::default()
    }

    /// A resolved table of `pairs`.
    fn table(pairs: &[(&str, &str)]) -> Result<NamedFilters, TestError> {
        let defs: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Ok(NamedFilters::resolve(&defs, &t())?)
    }

    /// The table most tests use: two entries, one referencing the other.
    fn sales() -> Result<NamedFilters, TestError> {
        table(&[
            ("sales", "to.user =~ '^5550'"),
            ("sales-failed", "@sales AND response_code >= 400"),
        ])
    }

    /// The rejection `check_expression` gives, or an error when it compiled.
    fn rejected(input: &str, filters: &NamedFilters) -> Result<FilterRejection, TestError> {
        match check_expression(input, filters, &t()) {
            Ok(expr) => Err(format!("'{input}' compiled to '{}'", expr.source()).into()),
            Err(r) => Ok(r),
        }
    }

    /// The error `compile_request` gives, or an error when it succeeded.
    fn refused(
        filter: Option<&str>,
        named: Option<&str>,
        filters: &NamedFilters,
    ) -> Result<FilterRequestError, TestError> {
        match compile_request(filter, named, filters, &t()) {
            Ok(expr) => Err(format!(
                "filter {filter:?} named {named:?} compiled to {:?}",
                expr.map(|e| e.source().to_owned())
            )
            .into()),
            Err(e) => Ok(e),
        }
    }

    /// The source of what `compile_request` compiled.
    fn compiled(
        filter: Option<&str>,
        named: Option<&str>,
        filters: &NamedFilters,
    ) -> Result<Option<String>, TestError> {
        Ok(compile_request(filter, named, filters, &t())?.map(|e| e.source().to_owned()))
    }

    /// The number after `at position` in a parser message.
    fn headline_position(message: &str) -> Option<usize> {
        let after = message.split("at position ").nth(1)?;
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    }

    // ── check_expression: success ───────────────────────────────────

    #[test]
    fn a_plain_expression_compiles_to_itself() -> Result<(), TestError> {
        let expr =
            check_expression("response_code >= 400", &sales()?, &t()).map_err(|r| r.message)?;
        assert_eq!(
            expr.source(),
            "response_code >= 400",
            "the source is the input"
        );
        Ok(())
    }

    #[test]
    fn an_alias_name_compiles_to_its_expansion() -> Result<(), TestError> {
        let expr = check_expression("slow-setup", &sales()?, &t()).map_err(|r| r.message)?;
        let want = crate::sip::dsl::expand_alias("slow-setup", &t()).ok_or("an alias")?;
        assert_eq!(expr.source(), want, "the alias expands with the thresholds");
        Ok(())
    }

    #[test]
    fn an_at_name_resolves_through_the_given_table() -> Result<(), TestError> {
        let expr = check_expression("@sales", &sales()?, &t()).map_err(|r| r.message)?;
        assert_eq!(
            expr.source(),
            "(to.user =~ '^5550')",
            "the table's expansion"
        );
        Ok(())
    }

    #[test]
    fn a_nested_at_name_resolves_fully() -> Result<(), TestError> {
        let expr = check_expression("@sales-failed", &sales()?, &t()).map_err(|r| r.message)?;
        assert_eq!(
            expr.source(),
            "((to.user =~ '^5550') AND response_code >= 400)",
            "both levels expand"
        );
        Ok(())
    }

    #[test]
    fn an_at_alias_resolves_inside_an_expression() -> Result<(), TestError> {
        let expr = check_expression("@one-way AND method == INVITE", &sales()?, &t())
            .map_err(|r| r.message)?;
        assert!(
            expr.source().starts_with("(one_way == true)"),
            "the alias reference expands: {}",
            expr.source()
        );
        Ok(())
    }

    #[test]
    fn surrounding_whitespace_is_accepted() -> Result<(), TestError> {
        let expr =
            check_expression("  state == InCall  ", &sales()?, &t()).map_err(|r| r.message)?;
        assert_eq!(expr.source(), "state == InCall", "the parser trims");
        Ok(())
    }

    #[test]
    fn a_quoted_at_sign_is_a_value_not_a_reference() -> Result<(), TestError> {
        let expr =
            check_expression("from.user == '@sales'", &table(&[])?, &t()).map_err(|r| r.message)?;
        assert_eq!(
            expr.source(),
            "from.user == '@sales'",
            "nothing expands in quotes"
        );
        Ok(())
    }

    #[test]
    fn the_compiled_source_matches_parse_filter_for_valid_inputs() -> Result<(), TestError> {
        // The installed table is empty in the lib tests, so with an empty
        // table both paths read the same text.
        let empty = table(&[])?;
        for input in [
            "problems",
            "method == INVITE",
            "rtp.loss > 2.0 OR rtp.jitter > 30",
            "NOT (state == Completed)",
            "  ua =~ 'Linphone'",
        ] {
            let ours = check_expression(input, &empty, &t()).map_err(|r| r.message)?;
            let theirs = crate::sip::dsl::parse_filter(input, &t())?;
            assert_eq!(ours.source(), theirs.source(), "same source for '{input}'");
        }
        Ok(())
    }

    // ── check_expression: failure ───────────────────────────────────

    #[test]
    fn trailing_input_reports_its_column() -> Result<(), TestError> {
        let r = rejected("state == InCall )", &table(&[])?)?;
        assert_eq!(
            r.position,
            Some(16),
            "the ')' is at column 16: {}",
            r.message
        );
        Ok(())
    }

    #[test]
    fn the_position_is_the_number_the_headline_prints() -> Result<(), TestError> {
        for input in [
            "state == InCall )",
            "method ==",
            "rtp.loss >",
            "from.user == 'a' AND",
            "(method == INVITE",
            "response_code >= 400 garbage",
            "staet == InCall",
        ] {
            let r = rejected(input, &table(&[])?)?;
            assert_eq!(
                r.position,
                headline_position(&r.message),
                "position and headline agree for '{input}': {}",
                r.message
            );
            assert!(
                r.position.is_some(),
                "'{input}' is a syntax error with a place"
            );
        }
        Ok(())
    }

    #[test]
    fn the_message_is_the_parsers_own_text() -> Result<(), TestError> {
        for input in [
            "state == InCall )",
            "method ==",
            "",
            "   ",
            "(method == INVITE",
            "staet == InCall",
        ] {
            let r = rejected(input, &table(&[])?)?;
            let theirs = match crate::sip::dsl::parse_filter(input, &t()) {
                Ok(_) => return Err(format!("parse_filter accepted '{input}'").into()),
                Err(e) => e.to_string(),
            };
            assert_eq!(r.message, theirs, "the parser's message for '{input}'");
        }
        Ok(())
    }

    #[test]
    fn an_empty_expression_has_no_position() -> Result<(), TestError> {
        let r = rejected("", &table(&[])?)?;
        assert_eq!(
            r.message, "filter expression is empty",
            "the parser's words"
        );
        assert_eq!(r.position, None, "nothing to point at");
        Ok(())
    }

    #[test]
    fn an_undefined_at_name_lists_the_given_tables_names() -> Result<(), TestError> {
        let filters = sales()?;
        let r = rejected("@nope AND method == INVITE", &filters)?;
        let want = crate::sip::named_filters::unknown_reference_message("nope", &filters);
        assert_eq!(r.message, want, "the one wording for an undefined name");
        assert!(r.message.contains("sales, sales-failed"), "{}", r.message);
        assert_eq!(r.position, None, "the parser names no place for it");
        Ok(())
    }

    #[test]
    fn an_error_inside_an_expansion_has_no_position() -> Result<(), TestError> {
        let r = rejected("@sales )", &sales()?)?;
        assert!(
            r.message.contains("at position"),
            "a syntax error: {}",
            r.message
        );
        assert_eq!(
            r.position, None,
            "the column is in the expansion, not the input"
        );
        Ok(())
    }

    #[test]
    fn too_deep_a_nesting_has_no_position() -> Result<(), TestError> {
        let input = format!("{}state == InCall{}", "(".repeat(60), ")".repeat(60));
        let r = rejected(&input, &table(&[])?)?;
        assert!(r.message.contains("nesting depth"), "{}", r.message);
        assert_eq!(r.position, None, "a limit, not a place");
        Ok(())
    }

    // ── check_expression: edge ──────────────────────────────────────

    #[test]
    fn the_position_counts_characters_not_bytes() -> Result<(), TestError> {
        let r = rejected("from.user == 'é' )", &table(&[])?)?;
        assert_eq!(r.position, Some(17), "the 'é' is one column: {}", r.message);
        Ok(())
    }

    #[test]
    fn leading_whitespace_does_not_move_the_position() -> Result<(), TestError> {
        let r = rejected("   state == InCall )", &table(&[])?)?;
        assert_eq!(
            r.position,
            Some(16),
            "a column in the trimmed text: {}",
            r.message
        );
        Ok(())
    }

    #[test]
    fn a_tab_and_newline_around_the_text_are_trimmed_too() -> Result<(), TestError> {
        let r = rejected("\t\nstate == InCall )\n", &table(&[])?)?;
        assert_eq!(r.position, Some(16), "{}", r.message);
        Ok(())
    }

    #[test]
    fn a_position_at_the_very_start_is_zero() -> Result<(), TestError> {
        let r = rejected(") state == InCall", &table(&[])?)?;
        assert_eq!(r.position, Some(0), "{}", r.message);
        Ok(())
    }

    #[test]
    fn an_alias_name_with_padding_is_not_an_alias() -> Result<(), TestError> {
        // As parse_filter reads it today: only the bare name is the alias.
        let ours = check_expression(" problems", &table(&[])?, &t());
        let theirs = crate::sip::dsl::parse_filter(" problems", &t());
        assert_eq!(
            ours.is_ok(),
            theirs.is_ok(),
            "the two agree on a padded alias"
        );
        Ok(())
    }

    #[test]
    fn an_at_sign_inside_a_bare_value_is_not_a_reference() -> Result<(), TestError> {
        let expr = check_expression("call_id == a1b2@example.com", &table(&[])?, &t())
            .map_err(|r| r.message)?;
        assert_eq!(expr.source(), "call_id == a1b2@example.com", "a value");
        Ok(())
    }

    #[test]
    fn a_long_expression_still_reports_its_column() -> Result<(), TestError> {
        let clause = "method == INVITE AND ".repeat(10);
        let input = format!("{clause}state == InCall )");
        let r = rejected(&input, &table(&[])?)?;
        assert_eq!(r.position, Some(input.len() - 1), "{}", r.message);
        assert_eq!(
            r.position,
            headline_position(&r.message),
            "the headline agrees"
        );
        Ok(())
    }

    #[test]
    fn a_reference_to_a_name_only_another_table_defines_is_refused() -> Result<(), TestError> {
        let r = rejected("@sales", &table(&[])?)?;
        assert!(
            r.message.contains("'@sales' is not a defined filter"),
            "{}",
            r.message
        );
        assert!(
            r.message.contains("Defined in [filters]: none"),
            "{}",
            r.message
        );
        Ok(())
    }

    // ── named_expansion and compile_request: success ────────────────

    #[test]
    fn named_selects_the_entrys_expansion() -> Result<(), TestError> {
        let got = compiled(None, Some("sales"), &sales()?)?;
        assert_eq!(
            got.as_deref(),
            Some("to.user =~ '^5550'"),
            "the entry's expansion"
        );
        Ok(())
    }

    #[test]
    fn named_selects_a_nested_entrys_full_expansion() -> Result<(), TestError> {
        let got = compiled(None, Some("sales-failed"), &sales()?)?;
        assert_eq!(
            got.as_deref(),
            Some("(to.user =~ '^5550') AND response_code >= 400"),
            "no reference is left"
        );
        Ok(())
    }

    #[test]
    fn named_accepts_a_built_in_alias() -> Result<(), TestError> {
        let got = compiled(None, Some("one-way"), &sales()?)?;
        assert_eq!(
            got.as_deref(),
            Some("one_way == true"),
            "the alias expansion"
        );
        Ok(())
    }

    #[test]
    fn named_accepts_every_built_in_alias() -> Result<(), TestError> {
        for alias in DIAGNOSTIC_ALIASES {
            let got = compiled(None, Some(alias), &table(&[])?)?;
            let want = crate::sip::dsl::expand_alias(alias, &t()).ok_or("an alias")?;
            assert_eq!(got, Some(want), "named={alias}");
        }
        Ok(())
    }

    #[test]
    fn named_selects_what_the_at_reference_selects() -> Result<(), TestError> {
        let filters = sales()?;
        for name in ["sales", "sales-failed", "problems"] {
            let by_name = compile_request(None, Some(name), &filters, &t())?.ok_or("some")?;
            let by_ref =
                compile_request(Some(&format!("@{name}")), None, &filters, &t())?.ok_or("some")?;
            assert_eq!(
                format!("({})", by_name.source()),
                by_ref.source(),
                "named={name} is filter=@{name}"
            );
        }
        Ok(())
    }

    #[test]
    fn neither_parameter_is_no_filter() -> Result<(), TestError> {
        assert_eq!(
            compiled(None, None, &sales()?)?,
            None,
            "no filter asked for"
        );
        Ok(())
    }

    #[test]
    fn filter_alone_compiles_as_before() -> Result<(), TestError> {
        let got = compiled(Some("method == INVITE"), None, &sales()?)?;
        assert_eq!(got.as_deref(), Some("method == INVITE"), "unchanged");
        Ok(())
    }

    #[test]
    fn filter_with_an_at_name_still_resolves() -> Result<(), TestError> {
        let got = compiled(Some("@sales AND method == INVITE"), None, &sales()?)?;
        assert_eq!(
            got.as_deref(),
            Some("(to.user =~ '^5550') AND method == INVITE"),
            "the reference expands"
        );
        Ok(())
    }

    #[test]
    fn named_expansion_returns_the_text() -> Result<(), TestError> {
        let text = named_expansion("sales", &sales()?, &t())?;
        assert_eq!(text, "to.user =~ '^5550'", "the expansion");
        Ok(())
    }

    #[test]
    fn accepted_names_lists_the_table_then_the_aliases() -> Result<(), TestError> {
        let names = accepted_names(&sales()?);
        let mut want = vec!["sales".to_owned(), "sales-failed".to_owned()];
        want.extend(DIAGNOSTIC_ALIASES.iter().map(|a| (*a).to_owned()));
        assert_eq!(names, want, "table names in order, then the aliases");
        Ok(())
    }

    #[test]
    fn accepted_names_of_an_empty_table_is_the_aliases() -> Result<(), TestError> {
        let names = accepted_names(&table(&[])?);
        assert_eq!(names.len(), DIAGNOSTIC_ALIASES.len(), "{names:?}");
        Ok(())
    }

    // ── compile_request: failure ────────────────────────────────────

    #[test]
    fn both_parameters_are_refused() -> Result<(), TestError> {
        let e = refused(Some("method == INVITE"), Some("sales"), &sales()?)?;
        assert_eq!(e, FilterRequestError::Conflict, "two filters named");
        assert_eq!(e.param(), None, "no one parameter is at fault");
        assert_eq!(e.to_string(), CONFLICT_MESSAGE, "the message");
        Ok(())
    }

    #[test]
    fn both_parameters_are_refused_even_when_both_name_the_same_filter() -> Result<(), TestError> {
        let e = refused(Some("@sales"), Some("sales"), &sales()?)?;
        assert_eq!(e, FilterRequestError::Conflict, "still two parameters");
        Ok(())
    }

    #[test]
    fn an_unknown_name_is_refused_with_the_names_defined() -> Result<(), TestError> {
        let filters = sales()?;
        let e = refused(None, Some("support"), &filters)?;
        let message = crate::sip::named_filters::unknown_reference_message("support", &filters);
        assert_eq!(
            e,
            FilterRequestError::UnknownName {
                name: "support".into(),
                message: message.clone()
            },
            "the name and the reason"
        );
        assert_eq!(e.to_string(), message, "the reason is the message");
        assert_eq!(e.param(), Some(FilterParam::Named), "about `named`");
        Ok(())
    }

    #[test]
    fn an_unknown_name_on_an_empty_table_says_none_are_defined() -> Result<(), TestError> {
        let e = refused(None, Some("sales"), &table(&[])?)?;
        assert!(e.to_string().contains("Defined in [filters]: none"), "{e}");
        assert!(
            e.to_string().contains("problems"),
            "the aliases are listed: {e}"
        );
        Ok(())
    }

    #[test]
    fn an_empty_name_is_refused() -> Result<(), TestError> {
        let e = refused(None, Some(""), &sales()?)?;
        assert_eq!(e, FilterRequestError::EmptyName, "no name");
        assert_eq!(e.to_string(), EMPTY_NAME_MESSAGE, "the message");
        assert_eq!(e.param(), Some(FilterParam::Named), "about `named`");
        Ok(())
    }

    #[test]
    fn a_lone_at_sign_is_an_empty_name() -> Result<(), TestError> {
        let e = refused(None, Some("@"), &sales()?)?;
        assert_eq!(e, FilterRequestError::EmptyName, "nothing after the @");
        Ok(())
    }

    #[test]
    fn an_expression_in_named_is_refused_as_an_unknown_name() -> Result<(), TestError> {
        let e = refused(None, Some("method == INVITE"), &sales()?)?;
        assert!(
            matches!(e, FilterRequestError::UnknownName { ref name, .. } if name == "method == INVITE"),
            "an expression is not a name: {e:?}"
        );
        Ok(())
    }

    #[test]
    fn an_invalid_filter_is_refused_with_its_position() -> Result<(), TestError> {
        let e = refused(Some("state == InCall )"), None, &sales()?)?;
        let FilterRequestError::Invalid { param, rejection } = &e else {
            return Err(format!("not Invalid: {e:?}").into());
        };
        assert_eq!(*param, FilterParam::Filter, "about `filter`");
        assert_eq!(rejection.position, Some(16), "{}", rejection.message);
        assert_eq!(e.to_string(), rejection.message, "the parser's message");
        Ok(())
    }

    #[test]
    fn an_undefined_reference_in_filter_is_invalid_filter() -> Result<(), TestError> {
        let e = refused(Some("@support"), None, &sales()?)?;
        assert_eq!(
            e.param(),
            Some(FilterParam::Filter),
            "about `filter`: {e:?}"
        );
        assert!(
            e.to_string().contains("'@support' is not a defined filter"),
            "{e}"
        );
        Ok(())
    }

    // ── named: edge ─────────────────────────────────────────────────

    #[test]
    fn a_leading_at_sign_in_named_is_accepted() -> Result<(), TestError> {
        let got = compiled(None, Some("@sales"), &sales()?)?;
        assert_eq!(
            got.as_deref(),
            Some("to.user =~ '^5550'"),
            "@sales is sales"
        );
        Ok(())
    }

    #[test]
    fn only_one_leading_at_sign_is_accepted() -> Result<(), TestError> {
        let e = refused(None, Some("@@sales"), &sales()?)?;
        assert!(
            matches!(e, FilterRequestError::UnknownName { ref name, .. } if name == "@sales"),
            "{e:?}"
        );
        Ok(())
    }

    #[test]
    fn a_padded_name_is_not_trimmed() -> Result<(), TestError> {
        let e = refused(None, Some(" sales"), &sales()?)?;
        assert!(
            matches!(e, FilterRequestError::UnknownName { ref name, .. } if name == " sales"),
            "names are exact: {e:?}"
        );
        Ok(())
    }

    #[test]
    fn names_are_case_sensitive() -> Result<(), TestError> {
        let e = refused(None, Some("Sales"), &sales()?)?;
        assert!(matches!(e, FilterRequestError::UnknownName { .. }), "{e:?}");
        Ok(())
    }

    #[test]
    fn an_empty_filter_with_a_name_is_still_a_conflict() -> Result<(), TestError> {
        let e = refused(Some(""), Some("sales"), &sales()?)?;
        assert_eq!(e, FilterRequestError::Conflict, "both were given");
        Ok(())
    }

    #[test]
    fn an_empty_filter_alone_is_the_parsers_empty_refusal() -> Result<(), TestError> {
        let e = refused(Some(""), None, &sales()?)?;
        assert_eq!(e.to_string(), "filter expression is empty", "as today");
        Ok(())
    }

    #[test]
    fn a_table_entry_shadows_nothing_built_in() -> Result<(), TestError> {
        // A [filters] entry cannot take an alias name, so `problems` is
        // always the alias, whatever the table holds.
        let got = compiled(None, Some("problems"), &sales()?)?;
        let want = crate::sip::dsl::expand_alias("problems", &t()).ok_or("alias")?;
        assert_eq!(got, Some(want), "the alias");
        Ok(())
    }

    #[test]
    fn the_unknown_name_message_keeps_a_unicode_name_intact() -> Result<(), TestError> {
        let e = refused(None, Some("vendas-é"), &sales()?)?;
        assert!(e.to_string().contains("'@vendas-é'"), "{e}");
        Ok(())
    }

    #[test]
    fn param_names_are_the_request_spellings() {
        assert_eq!(FilterParam::Filter.name(), "filter", "filter");
        assert_eq!(FilterParam::Named.name(), "named", "named");
    }
}
