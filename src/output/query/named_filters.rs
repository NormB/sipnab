// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The run's `[filters]` table as the query surfaces list it, and the answer
//! a filter validation gives.
//!
//! [`named_filter_list`] builds [`NamedFilterList`]: `GET /v1/filters`
//! serializes it and the MCP `list_named_filters` tool returns it, so both
//! list the same names in the same order with the same definitions.
//! [`filter_validation`] builds [`FilterValidation`], the answer of
//! `GET /v1/filters/validate`; its `error` and `position` are the ones the
//! MCP `validate_filter` tool reports, from the same compile step
//! ([`crate::sip::filter_request::check_expression`]).

use crate::sip::dsl::AliasThresholds;
use crate::sip::filter_request::check_expression;
use crate::sip::named_filters::NamedFilters;

/// One `[filters]` entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct NamedFilterRow {
    /// The entry's name: what `named` takes and what `@name` refers to.
    pub name: String,
    /// The definition as the config file writes it, `@name` references
    /// included.
    pub definition: String,
}

/// The `[filters]` table this run started with.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct NamedFilterList {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// Every entry, in name order. Empty when the config defines none.
    pub filters: Vec<NamedFilterRow>,
}

/// The `[filters]` table `filters` holds, one row per entry, in name order.
#[must_use]
pub fn named_filter_list(filters: &NamedFilters) -> NamedFilterList {
    NamedFilterList {
        schema_version: 1,
        filters: filters
            .names()
            .map(|name| NamedFilterRow {
                name: name.to_owned(),
                definition: filters.definition(name).unwrap_or_default().to_owned(),
            })
            .collect(),
    }
}

/// Whether a filter expression compiles, and where it stopped when it did
/// not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct FilterValidation {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// The expression as submitted, echoed verbatim.
    pub expr: String,
    /// Whether the expression compiled.
    pub valid: bool,
    /// The parser's message when it did not; the text a `filter` parameter's
    /// `400` carries after `filter: `. Null when it compiled.
    pub error: Option<String>,
    /// Where the parser stopped: the 0-based character column in the
    /// expression with its leading and trailing whitespace removed, the number
    /// `error` prints after `at position`. Null when it compiled, when the
    /// parser names no place (an empty expression, an undefined `@name`, a
    /// depth or size limit), and when the error is inside the expansion of an
    /// alias or an `@name`.
    pub position: Option<usize>,
}

/// Validate `expr` against the `[filters]` table `filters` and the alias
/// thresholds `t`.
#[must_use]
pub fn filter_validation(
    expr: &str,
    filters: &NamedFilters,
    t: &AliasThresholds,
) -> FilterValidation {
    let (error, position) = match check_expression(expr, filters, t) {
        Ok(_) => (None, None),
        Err(rejection) => (Some(rejection.message), rejection.position),
    };
    FilterValidation {
        schema_version: 1,
        expr: expr.to_owned(),
        valid: error.is_none(),
        error,
        position,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    type TestError = Box<dyn std::error::Error>;

    fn t() -> AliasThresholds {
        AliasThresholds::default()
    }

    fn table(pairs: &[(&str, &str)]) -> Result<NamedFilters, TestError> {
        let defs: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Ok(NamedFilters::resolve(&defs, &t())?)
    }

    fn row(name: &str, definition: &str) -> NamedFilterRow {
        NamedFilterRow {
            name: name.to_owned(),
            definition: definition.to_owned(),
        }
    }

    // ── named_filter_list ───────────────────────────────────────────

    #[test]
    fn the_list_holds_every_entry_in_name_order() -> Result<(), TestError> {
        let list = named_filter_list(&table(&[
            ("zeta", "method == BYE"),
            ("alpha", "method == INVITE"),
            ("mid", "state == InCall"),
        ])?);
        assert_eq!(
            list.filters,
            vec![
                row("alpha", "method == INVITE"),
                row("mid", "state == InCall"),
                row("zeta", "method == BYE"),
            ],
            "every entry, sorted by name"
        );
        Ok(())
    }

    #[test]
    fn a_definition_is_listed_as_written_with_its_references() -> Result<(), TestError> {
        let list = named_filter_list(&table(&[
            ("sales", "to.user =~ '^5550'"),
            ("sales-failed", "@sales AND response_code >= 400"),
        ])?);
        assert_eq!(
            list.filters[1],
            row("sales-failed", "@sales AND response_code >= 400"),
            "the reference is kept, not expanded"
        );
        Ok(())
    }

    #[test]
    fn a_reference_to_a_built_in_alias_is_kept_as_written() -> Result<(), TestError> {
        let list = named_filter_list(&table(&[("bad-media", "@one-way OR @problems")])?);
        assert_eq!(
            list.filters,
            vec![row("bad-media", "@one-way OR @problems")],
            "kept"
        );
        Ok(())
    }

    #[test]
    fn an_empty_table_lists_nothing() -> Result<(), TestError> {
        let list = named_filter_list(&table(&[])?);
        assert!(list.filters.is_empty(), "no entries: {list:?}");
        assert_eq!(list.schema_version, 1, "versioned");
        Ok(())
    }

    #[test]
    fn the_list_serializes_name_and_definition_only() -> Result<(), TestError> {
        let list = named_filter_list(&table(&[("sales", "to.user =~ '^5550'")])?);
        let json = serde_json::to_value(&list)?;
        assert_eq!(
            json,
            serde_json::json!({
                "schema_version": 1,
                "filters": [{"name": "sales", "definition": "to.user =~ '^5550'"}]
            }),
            "the wire shape"
        );
        Ok(())
    }

    #[test]
    fn a_definition_keeps_its_quotes_and_spacing() -> Result<(), TestError> {
        let written = "ua   =~   \"Linphone 5\"";
        let list = named_filter_list(&table(&[("phones", written)])?);
        assert_eq!(list.filters, vec![row("phones", written)], "byte for byte");
        Ok(())
    }

    // ── filter_validation ───────────────────────────────────────────

    #[test]
    fn a_valid_expression_validates() -> Result<(), TestError> {
        let v = filter_validation("method == INVITE", &table(&[])?, &t());
        assert_eq!(
            v,
            FilterValidation {
                schema_version: 1,
                expr: "method == INVITE".into(),
                valid: true,
                error: None,
                position: None,
            },
            "valid, no error"
        );
        Ok(())
    }

    #[test]
    fn an_invalid_expression_reports_message_and_position() -> Result<(), TestError> {
        let v = filter_validation("state == InCall )", &table(&[])?, &t());
        assert!(!v.valid, "not valid: {v:?}");
        assert_eq!(v.position, Some(16), "the ')' column");
        let message = v.error.ok_or("an error")?;
        assert!(message.contains(" at position 16: ')'"), "{message}");
        Ok(())
    }

    #[test]
    fn the_expression_is_echoed_verbatim() -> Result<(), TestError> {
        let v = filter_validation("  method ==  ", &table(&[])?, &t());
        assert_eq!(v.expr, "  method ==  ", "untrimmed echo");
        assert!(!v.valid, "{v:?}");
        Ok(())
    }

    #[test]
    fn an_undefined_name_is_invalid_without_a_position() -> Result<(), TestError> {
        let v = filter_validation("@nope", &table(&[])?, &t());
        assert!(!v.valid, "{v:?}");
        assert_eq!(v.position, None, "no place");
        assert!(
            v.error
                .as_deref()
                .is_some_and(|e| e.contains("'@nope' is not a defined filter")),
            "{v:?}"
        );
        Ok(())
    }

    #[test]
    fn a_named_reference_validates_through_the_table() -> Result<(), TestError> {
        let v = filter_validation("@sales", &table(&[("sales", "to.user =~ '^5550'")])?, &t());
        assert!(v.valid, "{v:?}");
        Ok(())
    }

    #[test]
    fn the_validation_serializes_with_null_fields() -> Result<(), TestError> {
        let v = filter_validation("problems", &table(&[])?, &t());
        let json = serde_json::to_value(&v)?;
        assert_eq!(
            json,
            serde_json::json!({
                "schema_version": 1,
                "expr": "problems",
                "valid": true,
                "error": null,
                "position": null
            }),
            "null, not absent"
        );
        Ok(())
    }

    #[test]
    fn an_empty_expression_is_invalid_without_a_position() -> Result<(), TestError> {
        let v = filter_validation("", &table(&[])?, &t());
        assert!(!v.valid, "{v:?}");
        assert_eq!(
            v.error.as_deref(),
            Some("filter expression is empty"),
            "{v:?}"
        );
        assert_eq!(v.position, None, "{v:?}");
        Ok(())
    }
}
