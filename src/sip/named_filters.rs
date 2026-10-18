// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Operator-defined filters: the `[filters]` table and `@name` references.
//!
//! A filter written once in the config is used by name wherever sipnab takes
//! a filter expression: `--filter`, `--export-vcon-when`, an export rule's
//! `when`, a REST `filter` parameter, an MCP tool's `filter`. A name can
//! appear inside another expression, including another named filter, and the
//! built-in diagnostic aliases can be referenced the same way (`@problems`).
//!
//! Every definition is resolved once, at startup ([`NamedFilters::resolve`]):
//! references are expanded, cycles and unknown names are refused, and each
//! expansion must parse. A run therefore either starts with every name usable
//! or does not start, and the error names the filter at fault.
//!
//! The expansion is textual. `@name` outside a quoted string becomes the
//! parenthesized expansion, so `@a AND @b` keeps the precedence each
//! definition was written with.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::dsl::{AliasThresholds, DIAGNOSTIC_ALIASES, FilterExpr, expand_alias};

/// The longest name a `[filters]` entry may have, in bytes.
pub const MAX_FILTER_NAME_LEN: usize = 64;

/// Why the `[filters]` table cannot be used. Each variant names the filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamedFilterError {
    /// The name is empty, too long, or holds a character other than an ASCII
    /// letter, digit, `-` or `_`, or does not start with a letter or digit.
    BadName(String),
    /// The name is a built-in alias, which keeps its meaning.
    BuiltIn(String),
    /// `filter` references `missing`, which nothing defines.
    Unknown {
        /// The filter whose definition holds the reference.
        filter: String,
        /// The name it references.
        missing: String,
    },
    /// The definitions reference each other in a loop, listed in order.
    Cycle(Vec<String>),
    /// The expansion of `filter` is not a valid expression.
    Invalid {
        /// The filter whose expansion failed.
        filter: String,
        /// The parser's message.
        message: String,
    },
}

impl std::fmt::Display for NamedFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadName(name) => write!(
                f,
                "[filters] name '{name}' is not usable: a name is 1 to \
                 {MAX_FILTER_NAME_LEN} ASCII letters, digits, '-' or '_', \
                 starting with a letter or digit"
            ),
            Self::BuiltIn(name) => write!(
                f,
                "[filters] name '{name}' is a built-in alias and keeps its \
                 built-in meaning; choose another name"
            ),
            Self::Unknown { filter, missing } => write!(
                f,
                "[filters] '{filter}' references '@{missing}', which no \
                 [filters] entry or built-in alias defines"
            ),
            Self::Cycle(path) => write!(
                f,
                "[filters] entries reference each other in a loop: {}",
                path.iter()
                    .map(|n| format!("@{n}"))
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ),
            Self::Invalid { filter, message } => {
                write!(
                    f,
                    "[filters] '{filter}' is not a valid filter expression: {message}"
                )
            }
        }
    }
}

impl std::error::Error for NamedFilterError {}

/// The resolved `[filters]` table: every name mapped to its full expansion,
/// with no `@` reference left in it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamedFilters {
    /// Name to expansion.
    expanded: BTreeMap<String, String>,
}

impl NamedFilters {
    /// Resolve the `[filters]` definitions.
    ///
    /// # Errors
    ///
    /// The first problem found, in name order: a bad name, a name that is a
    /// built-in alias, an unknown reference, a cycle, or an expansion that
    /// does not parse.
    pub fn resolve(
        defs: &BTreeMap<String, String>,
        t: &AliasThresholds,
    ) -> Result<Self, NamedFilterError> {
        for name in defs.keys() {
            if !valid_name(name) {
                return Err(NamedFilterError::BadName(name.clone()));
            }
            if DIAGNOSTIC_ALIASES.contains(&name.as_str()) {
                return Err(NamedFilterError::BuiltIn(name.clone()));
            }
        }
        let mut expanded = BTreeMap::new();
        for name in defs.keys() {
            let mut path = Vec::new();
            let text = expand_definition(name, defs, t, &mut path, &mut expanded)?;
            FilterExpr::parse(&text).map_err(|e| NamedFilterError::Invalid {
                filter: name.clone(),
                message: e.to_string(),
            })?;
        }
        Ok(Self { expanded })
    }

    /// The defined names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.expanded.keys().map(String::as_str)
    }

    /// The full expansion of `name`, if it is defined.
    #[must_use]
    pub fn expansion(&self, name: &str) -> Option<&str> {
        self.expanded.get(name).map(String::as_str)
    }

    /// `input` with every `@name` outside a quoted string replaced by its
    /// parenthesized expansion. A name this table does not define and that is
    /// not a built-in alias is left as written, for the parser to report.
    #[must_use]
    pub fn substitute(&self, input: &str, t: &AliasThresholds) -> String {
        substitute_refs(input, |name| {
            self.expanded
                .get(name)
                .cloned()
                .or_else(|| expand_alias(name, t))
        })
    }
}

/// Whether `name` is usable as a `[filters]` key.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_FILTER_NAME_LEN
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|&b| is_name_byte(b))
}

/// Whether `b` may appear in a filter name.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Expand `name`'s definition, recursively, memoizing into `done`.
fn expand_definition(
    name: &str,
    defs: &BTreeMap<String, String>,
    t: &AliasThresholds,
    path: &mut Vec<String>,
    done: &mut BTreeMap<String, String>,
) -> Result<String, NamedFilterError> {
    if let Some(text) = done.get(name) {
        return Ok(text.clone());
    }
    if let Some(start) = path.iter().position(|n| n == name) {
        let mut cycle = path[start..].to_vec();
        cycle.push(name.to_owned());
        return Err(NamedFilterError::Cycle(cycle));
    }
    let Some(def) = defs.get(name) else {
        // Reached only through a reference; the caller reports it.
        return Err(NamedFilterError::Unknown {
            filter: path.last().cloned().unwrap_or_default(),
            missing: name.to_owned(),
        });
    };
    path.push(name.to_owned());
    let mut failure = None;
    let text = substitute_refs(def, |reference| {
        if failure.is_some() {
            return None;
        }
        if defs.contains_key(reference) {
            match expand_definition(reference, defs, t, path, done) {
                Ok(text) => Some(text),
                Err(e) => {
                    failure = Some(e);
                    None
                }
            }
        } else if let Some(alias) = expand_alias(reference, t) {
            Some(alias)
        } else {
            failure = Some(NamedFilterError::Unknown {
                filter: name.to_owned(),
                missing: reference.to_owned(),
            });
            None
        }
    });
    path.pop();
    if let Some(e) = failure {
        return Err(e);
    }
    done.insert(name.to_owned(), text.clone());
    Ok(text)
}

/// The byte spans of each `@name` outside a quoted string, `@` included.
///
/// A reference begins an atom, so its `@` is the first character of the
/// expression or follows whitespace or `(`. A `@` inside a word, as in the
/// bare value `call_id == a1b2@example.com`, is part of that value.
///
/// Quotes follow the DSL's string literals: `'…'` or `"…"`, with a backslash
/// escaping the next character. The one scanner both [`substitute_refs`] and
/// [`first_reference`] use, so the two cannot disagree about what is quoted.
fn reference_spans(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                }
            }
            None if b == b'\'' || b == b'"' => quote = Some(b),
            None if b == b'@'
                && (i == 0 || bytes[i - 1].is_ascii_whitespace() || bytes[i - 1] == b'(') =>
            {
                let mut end = i + 1;
                while end < bytes.len() && is_name_byte(bytes[end]) {
                    end += 1;
                }
                if end > i + 1 {
                    spans.push((i, end));
                    i = end;
                    continue;
                }
            }
            None => {}
        }
        i += 1;
    }
    spans
}

/// Replace each `@name` outside a quoted string with `(lookup(name))`.
/// A reference `lookup` answers `None` for is left as written.
fn substitute_refs(input: &str, mut lookup: impl FnMut(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut copied = 0;
    for (start, end) in reference_spans(input) {
        if let Some(text) = lookup(&input[start + 1..end]) {
            out.push_str(&input[copied..start]);
            out.push('(');
            out.push_str(&text);
            out.push(')');
            copied = end;
        }
    }
    out.push_str(&input[copied..]);
    out
}

/// Every `@name` referenced outside a quoted string in `input`, each once, in
/// the order it first appears.
#[must_use]
pub fn references(input: &str) -> Vec<&str> {
    let mut names: Vec<&str> = Vec::new();
    for (start, end) in reference_spans(input) {
        let name = &input[start + 1..end];
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// The first `@name` reference outside a quoted string in `input`, if any.
#[must_use]
pub fn first_reference(input: &str) -> Option<&str> {
    reference_spans(input)
        .first()
        .map(|&(start, end)| &input[start + 1..end])
}

/// What sipnab says about `@name` when nothing defines it: the name, the
/// `[filters]` names `filters` defines, and the built-in aliases. The one
/// wording for every surface.
#[must_use]
pub fn unknown_reference_message(name: &str, filters: &NamedFilters) -> String {
    let defined: Vec<&str> = filters.names().collect();
    format!(
        "'@{name}' is not a defined filter. Defined in [filters]: {}. Built-in aliases: {}",
        if defined.is_empty() {
            "none".to_owned()
        } else {
            defined.join(", ")
        },
        DIAGNOSTIC_ALIASES.join(", ")
    )
}

/// The process's resolved `[filters]`, installed once at startup.
static INSTALLED: OnceLock<NamedFilters> = OnceLock::new();

/// Install the run's resolved `[filters]`. The first call wins; a later call
/// returns `false` and changes nothing, so a filter cannot change meaning
/// partway through a run.
pub fn install(filters: NamedFilters) -> bool {
    INSTALLED.set(filters).is_ok()
}

/// The run's resolved `[filters]`, or an empty table when none was installed.
#[must_use]
pub fn installed() -> &'static NamedFilters {
    static EMPTY: OnceLock<NamedFilters> = OnceLock::new();
    INSTALLED
        .get()
        .unwrap_or_else(|| EMPTY.get_or_init(NamedFilters::default))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    fn defs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn t() -> AliasThresholds {
        AliasThresholds::default()
    }

    /// Each reference once, in first-appearance order, and none inside a
    /// quoted string.
    #[test]
    fn references_lists_each_name_once_outside_quotes() {
        assert_eq!(
            references("@a OR (@b AND @a) OR to.user == '@c' OR \"@d\""),
            vec!["a", "b"]
        );
        assert!(references("method == 'INVITE'").is_empty());
    }

    #[test]
    fn a_reference_expands_to_its_parenthesized_definition() -> Result<(), TestError> {
        let f = NamedFilters::resolve(
            &defs(&[
                ("carrier-a", "src.ip in_subnet '203.0.113.0/24'"),
                ("sales", "@carrier-a AND to.user =~ '^8'"),
            ]),
            &t(),
        )?;
        assert_eq!(
            f.expansion("sales"),
            Some("(src.ip in_subnet '203.0.113.0/24') AND to.user =~ '^8'")
        );
        assert_eq!(
            f.substitute("@sales OR method == 'BYE'", &t()),
            "((src.ip in_subnet '203.0.113.0/24') AND to.user =~ '^8') OR method == 'BYE'"
        );
        Ok(())
    }

    #[test]
    fn a_built_in_alias_can_be_referenced() -> Result<(), TestError> {
        let f = NamedFilters::resolve(&defs(&[("bad", "@one-way AND to.user == '7000'")]), &t())?;
        assert_eq!(
            f.expansion("bad"),
            Some("(one_way == true) AND to.user == '7000'")
        );
        assert_eq!(f.substitute("@nat-issues", &t()), "(nat_mismatch == true)");
        Ok(())
    }

    #[test]
    fn an_at_sign_inside_a_quoted_string_is_not_a_reference() -> Result<(), TestError> {
        let f = NamedFilters::resolve(&defs(&[("x", "method == 'INVITE'")]), &t())?;
        for input in [
            "from.user == '@x'",
            "header.Contact =~ \"sip:@x\"",
            "ua == 'a\\'@x'",
        ] {
            assert_eq!(f.substitute(input, &t()), input, "{input}");
        }
        assert_eq!(first_reference("ua == '@x' AND @y"), Some("y"));
        assert_eq!(first_reference("ua == '@x'"), None);
        Ok(())
    }

    #[test]
    fn an_unknown_reference_is_refused_naming_both_filters() {
        let e = NamedFilters::resolve(&defs(&[("a", "@nope OR method == 'BYE'")]), &t());
        assert_eq!(
            e,
            Err(NamedFilterError::Unknown {
                filter: "a".into(),
                missing: "nope".into()
            })
        );
    }

    #[test]
    fn a_cycle_is_refused_with_its_path() {
        let e = NamedFilters::resolve(&defs(&[("a", "@b"), ("b", "@c"), ("c", "@a")]), &t());
        assert_eq!(
            e,
            Err(NamedFilterError::Cycle(vec![
                "a".into(),
                "b".into(),
                "c".into(),
                "a".into()
            ]))
        );
        let selfref = NamedFilters::resolve(&defs(&[("a", "@a")]), &t());
        assert_eq!(
            selfref,
            Err(NamedFilterError::Cycle(vec!["a".into(), "a".into()]))
        );
    }

    #[test]
    fn a_built_in_name_and_a_bad_name_are_refused() {
        assert_eq!(
            NamedFilters::resolve(&defs(&[("problems", "method == 'BYE'")]), &t()),
            Err(NamedFilterError::BuiltIn("problems".into()))
        );
        for bad in [
            "",
            "-a",
            "a b",
            "a.b",
            "é",
            &"x".repeat(MAX_FILTER_NAME_LEN + 1),
        ] {
            assert_eq!(
                NamedFilters::resolve(&defs(&[(bad, "method == 'BYE'")]), &t()),
                Err(NamedFilterError::BadName(bad.into())),
                "{bad:?}"
            );
        }
        assert!(valid_name(&"x".repeat(MAX_FILTER_NAME_LEN)));
    }

    #[test]
    fn an_expansion_that_does_not_parse_is_refused() {
        let e = NamedFilters::resolve(&defs(&[("a", "method === 'BYE'")]), &t());
        assert!(
            matches!(&e, Err(NamedFilterError::Invalid { filter, .. }) if filter == "a"),
            "{e:?}"
        );
    }

    #[test]
    fn an_unknown_reference_in_an_input_is_left_for_the_parser() -> Result<(), TestError> {
        let f = NamedFilters::resolve(&defs(&[("a", "method == 'BYE'")]), &t())?;
        assert_eq!(f.substitute("@a OR @b", &t()), "(method == 'BYE') OR @b");
        Ok(())
    }

    #[test]
    fn every_error_names_the_filter() {
        let cases = [
            NamedFilterError::BadName("x y".into()),
            NamedFilterError::BuiltIn("problems".into()),
            NamedFilterError::Unknown {
                filter: "sales".into(),
                missing: "nope".into(),
            },
            NamedFilterError::Cycle(vec!["a".into(), "a".into()]),
            NamedFilterError::Invalid {
                filter: "sales".into(),
                message: "m".into(),
            },
        ];
        for (e, want) in cases
            .iter()
            .zip(["x y", "problems", "sales", "@a -> @a", "sales"])
        {
            assert!(e.to_string().contains(want), "{e}");
        }
    }
}
