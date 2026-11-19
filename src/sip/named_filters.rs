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
//! or does not start, and the error names the filter at fault. The terminal
//! UI's `F2` save adds a name to the running process's table
//! ([`publish`]); it is checked the same way before it is added.
//!
//! The expansion is textual. `@name` outside a quoted string becomes the
//! parenthesized expansion, so `@a AND @b` keeps the precedence each
//! definition was written with.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use parking_lot::RwLock;

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
    /// A save would define a name the table already defines.
    Duplicate(String),
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
            Self::Duplicate(name) => write!(
                f,
                "[filters] already defines '{name}'; choose another name, or \
                 edit that entry in the config file"
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
    /// Name to definition as written, `@name` references kept: what a save
    /// writes back to the config, and the text [`Self::with_added`] resolves
    /// the table again from.
    definitions: BTreeMap<String, String>,
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
        Ok(Self {
            expanded,
            definitions: defs.clone(),
        })
    }

    /// The table with `name` defined as `definition` added, resolved again
    /// by the rules of [`Self::resolve`]. `self` is not changed.
    ///
    /// # Errors
    ///
    /// [`NamedFilterError::Duplicate`] when the table already defines
    /// `name`; otherwise what [`Self::resolve`] refuses for the new entry: a
    /// bad name, a built-in alias name, an unknown reference, a loop, or a
    /// definition that does not parse.
    pub fn with_added(
        &self,
        name: &str,
        definition: &str,
        t: &AliasThresholds,
    ) -> Result<Self, NamedFilterError> {
        if !valid_name(name) {
            return Err(NamedFilterError::BadName(name.to_owned()));
        }
        if self.definitions.contains_key(name) {
            return Err(NamedFilterError::Duplicate(name.to_owned()));
        }
        let mut defs = self.definitions.clone();
        defs.insert(name.to_owned(), definition.to_owned());
        Self::resolve(&defs, t)
    }

    /// The definition of `name` as written in `[filters]`, if it is defined.
    #[must_use]
    pub fn definition(&self, name: &str) -> Option<&str> {
        self.definitions.get(name).map(String::as_str)
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

/// A run's live `[filters]` table: installed at startup, replaced whole
/// when the terminal UI saves a name with `F2`, read as an `Arc` snapshot.
#[derive(Debug, Default)]
pub struct LiveTable {
    /// The current table; `None` until installed.
    slot: RwLock<Option<Arc<NamedFilters>>>,
}

impl LiveTable {
    /// An empty, uninstalled table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slot: RwLock::new(None),
        }
    }

    /// Install the startup table. The first call wins (a publish counts);
    /// a later call returns `false` and changes nothing.
    pub fn install(&self, filters: NamedFilters) -> bool {
        let mut slot = self.slot.write();
        if slot.is_some() {
            return false;
        }
        *slot = Some(Arc::new(filters));
        true
    }

    /// Replace the table whole. Snapshots already taken keep the table they
    /// were taken from; a filter already compiled keeps its meaning.
    pub fn publish(&self, filters: NamedFilters) {
        *self.slot.write() = Some(Arc::new(filters));
    }

    /// The current table: one read lock and one reference-count increment,
    /// taken when a filter is compiled, never per packet.
    #[must_use]
    pub fn snapshot(&self) -> Arc<NamedFilters> {
        static EMPTY: OnceLock<Arc<NamedFilters>> = OnceLock::new();
        self.slot.read().as_ref().map_or_else(
            || Arc::clone(EMPTY.get_or_init(|| Arc::new(NamedFilters::default()))),
            Arc::clone,
        )
    }
}

/// The process's resolved `[filters]`: installed at startup, replaced when
/// the terminal UI saves a name.
static LIVE: LiveTable = LiveTable::new();

/// Install the run's resolved `[filters]`. The first call wins; a later call
/// returns `false` and changes nothing.
pub fn install(filters: NamedFilters) -> bool {
    LIVE.install(filters)
}

/// Replace the run's table: the terminal UI's `F2` save calls it with the
/// table that holds the new name, so a filter compiled after it (by the
/// REST API, the MCP server or the terminal UI of this process) resolves
/// the name. A filter compiled before it is unchanged.
pub fn publish(filters: NamedFilters) {
    LIVE.publish(filters);
}

/// The run's resolved `[filters]` as it is now, or an empty table when none
/// was installed.
#[must_use]
pub fn installed() -> Arc<NamedFilters> {
    LIVE.snapshot()
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

/// [`NamedFilters::with_added`]: the table a save from the terminal UI
/// would leave, or the reason the save is refused.
#[cfg(test)]
mod adding_tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    fn t() -> AliasThresholds {
        AliasThresholds::default()
    }

    /// A table holding `sales` and `west`.
    fn table() -> Result<NamedFilters, TestError> {
        let mut defs = BTreeMap::new();
        defs.insert("sales".to_owned(), "to.user == '7000'".to_owned());
        defs.insert("west".to_owned(), "src.ip == '192.0.2.1'".to_owned());
        Ok(NamedFilters::resolve(&defs, &t())?)
    }

    // ── success ────────────────────────────────────────────────────────

    /// A new name joins the table with its expansion.
    #[test]
    fn a_new_name_is_added() -> Result<(), TestError> {
        let added = table()?.with_added("invites", "method == 'INVITE'", &t())?;
        assert_eq!(
            added.expansion("invites"),
            Some("method == 'INVITE'"),
            "the new name expands to its definition"
        );
        Ok(())
    }

    /// The names already defined stay, with the same expansions.
    #[test]
    fn the_existing_names_are_kept() -> Result<(), TestError> {
        let before = table()?;
        let added = before.with_added("invites", "method == 'INVITE'", &t())?;
        for name in ["sales", "west"] {
            assert_eq!(
                added.expansion(name),
                before.expansion(name),
                "{name} keeps its expansion"
            );
        }
        Ok(())
    }

    /// The names come back in order, the new one among them.
    #[test]
    fn names_stay_sorted_with_the_new_one() -> Result<(), TestError> {
        let added = table()?.with_added("north", "src.port == 5060", &t())?;
        let names: Vec<&str> = added.names().collect();
        assert_eq!(names, ["north", "sales", "west"], "sorted names");
        Ok(())
    }

    /// The table it was built from does not change.
    #[test]
    fn the_original_table_is_unchanged() -> Result<(), TestError> {
        let before = table()?;
        let copy = before.clone();
        let _ = before.with_added("north", "src.port == 5060", &t())?;
        assert_eq!(before, copy, "with_added does not change self");
        Ok(())
    }

    /// A definition may reference a name already in the table.
    #[test]
    fn a_reference_to_a_defined_name_is_expanded() -> Result<(), TestError> {
        let added = table()?.with_added("west-sales", "@west AND @sales", &t())?;
        assert_eq!(
            added.expansion("west-sales"),
            Some("(src.ip == '192.0.2.1') AND (to.user == '7000')"),
            "references expand in the new definition"
        );
        Ok(())
    }

    /// A definition may reference a built-in alias.
    #[test]
    fn a_reference_to_a_built_in_alias_is_expanded() -> Result<(), TestError> {
        let added = table()?.with_added("bad-sales", "@sales AND @one-way", &t())?;
        let text = added.expansion("bad-sales").ok_or("no expansion")?;
        assert!(
            text.contains("one_way == true") && !text.contains('@'),
            "the alias expands: {text}"
        );
        Ok(())
    }

    /// The definition as written is kept beside the expansion.
    #[test]
    fn the_definition_is_kept_as_written() -> Result<(), TestError> {
        let added = table()?.with_added("west-sales", "@west AND @sales", &t())?;
        assert_eq!(
            added.definition("west-sales"),
            Some("@west AND @sales"),
            "the definition keeps its references"
        );
        Ok(())
    }

    /// The definitions a table was resolved from can be read back.
    #[test]
    fn resolve_keeps_every_definition() -> Result<(), TestError> {
        let table = table()?;
        assert_eq!(
            table.definition("sales"),
            Some("to.user == '7000'"),
            "sales"
        );
        assert_eq!(
            table.definition("west"),
            Some("src.ip == '192.0.2.1'"),
            "west"
        );
        Ok(())
    }

    /// An empty table accepts a first name.
    #[test]
    fn an_empty_table_takes_a_first_name() -> Result<(), TestError> {
        let added = NamedFilters::default().with_added("first", "state == 'Failed'", &t())?;
        assert_eq!(added.names().count(), 1, "one name");
        Ok(())
    }

    /// The longest allowed name is accepted.
    #[test]
    fn a_name_of_the_maximum_length_is_accepted() -> Result<(), TestError> {
        let name = "a".repeat(MAX_FILTER_NAME_LEN);
        let added = table()?.with_added(&name, "src.port == 5060", &t())?;
        assert!(added.expansion(&name).is_some(), "64-byte name added");
        Ok(())
    }

    /// A name with digits, `-` and `_` is accepted.
    #[test]
    fn a_name_with_dash_underscore_and_digits_is_accepted() -> Result<(), TestError> {
        let added = table()?.with_added("pbx_2-west", "src.port == 5060", &t())?;
        assert!(added.expansion("pbx_2-west").is_some(), "added");
        Ok(())
    }

    /// An expression holding `OR` keeps its own grouping when referenced.
    #[test]
    fn an_or_definition_is_grouped_when_referenced() -> Result<(), TestError> {
        let added = table()?
            .with_added("either", "method == 'BYE' OR method == 'CANCEL'", &t())?
            .with_added("either-west", "@either AND @west", &t())?;
        assert_eq!(
            added.expansion("either-west"),
            Some("(method == 'BYE' OR method == 'CANCEL') AND (src.ip == '192.0.2.1')"),
            "the OR stays inside its parentheses"
        );
        Ok(())
    }

    // ── failure ────────────────────────────────────────────────────────

    /// A name the table already defines is refused, naming it.
    #[test]
    fn a_duplicate_name_is_refused() -> Result<(), TestError> {
        let err = table()?
            .with_added("sales", "method == 'INVITE'", &t())
            .err()
            .ok_or("a duplicate must be refused")?;
        assert_eq!(
            err,
            NamedFilterError::Duplicate("sales".into()),
            "duplicate"
        );
        Ok(())
    }

    /// The duplicate refusal says what to do.
    #[test]
    fn the_duplicate_message_names_the_filter_and_the_way_out() {
        let text = NamedFilterError::Duplicate("sales".into()).to_string();
        assert!(
            text.contains("'sales'") && text.contains("already defines"),
            "message: {text}"
        );
    }

    /// An empty name is refused.
    #[test]
    fn an_empty_name_is_refused() -> Result<(), TestError> {
        let err = table()?.with_added("", "method == 'INVITE'", &t()).err();
        assert_eq!(
            err,
            Some(NamedFilterError::BadName(String::new())),
            "empty name"
        );
        Ok(())
    }

    /// A name with a space is refused.
    #[test]
    fn a_name_with_a_space_is_refused() -> Result<(), TestError> {
        let err = table()?
            .with_added("my calls", "method == 'INVITE'", &t())
            .err();
        assert_eq!(
            err,
            Some(NamedFilterError::BadName("my calls".into())),
            "space"
        );
        Ok(())
    }

    /// A name one byte past the limit is refused.
    #[test]
    fn a_name_past_the_maximum_length_is_refused() -> Result<(), TestError> {
        let name = "a".repeat(MAX_FILTER_NAME_LEN + 1);
        let err = table()?.with_added(&name, "method == 'INVITE'", &t()).err();
        assert_eq!(err, Some(NamedFilterError::BadName(name)), "65 bytes");
        Ok(())
    }

    /// A name starting with `-` is refused.
    #[test]
    fn a_name_starting_with_a_dash_is_refused() -> Result<(), TestError> {
        let err = table()?.with_added("-x", "method == 'INVITE'", &t()).err();
        assert_eq!(
            err,
            Some(NamedFilterError::BadName("-x".into())),
            "leading dash"
        );
        Ok(())
    }

    /// A name written with its `@` is refused: the `@` is not part of a name.
    #[test]
    fn a_name_with_an_at_sign_is_refused() -> Result<(), TestError> {
        let err = table()?.with_added("@x", "method == 'INVITE'", &t()).err();
        assert_eq!(
            err,
            Some(NamedFilterError::BadName("@x".into())),
            "leading @"
        );
        Ok(())
    }

    /// A built-in alias name is refused.
    #[test]
    fn a_built_in_alias_name_is_refused() -> Result<(), TestError> {
        let err = table()?
            .with_added("problems", "method == 'INVITE'", &t())
            .err();
        assert_eq!(
            err,
            Some(NamedFilterError::BuiltIn("problems".into())),
            "alias"
        );
        Ok(())
    }

    /// A definition that does not parse is refused with the parser's message.
    #[test]
    fn an_invalid_expression_is_refused() -> Result<(), TestError> {
        let err = table()?
            .with_added("bad", "method === 'INVITE'", &t())
            .err()
            .ok_or("must be refused")?;
        assert!(
            matches!(&err, NamedFilterError::Invalid { filter, .. } if filter == "bad"),
            "invalid: {err:?}"
        );
        Ok(())
    }

    /// A reference to a name nothing defines is refused.
    #[test]
    fn an_unknown_reference_is_refused() -> Result<(), TestError> {
        let err = table()?.with_added("x", "@nosuch", &t()).err();
        assert_eq!(
            err,
            Some(NamedFilterError::Unknown {
                filter: "x".into(),
                missing: "nosuch".into()
            }),
            "unknown reference"
        );
        Ok(())
    }

    /// A definition that references itself is refused as a loop.
    #[test]
    fn a_self_reference_is_refused() -> Result<(), TestError> {
        let err = table()?.with_added("loop", "@loop", &t()).err();
        assert!(
            matches!(err, Some(NamedFilterError::Cycle(_))),
            "self reference: {err:?}"
        );
        Ok(())
    }

    /// An empty expression is refused.
    #[test]
    fn an_empty_expression_is_refused() -> Result<(), TestError> {
        let err = table()?.with_added("x", "", &t()).err();
        assert!(
            matches!(err, Some(NamedFilterError::Invalid { .. })),
            "empty: {err:?}"
        );
        Ok(())
    }

    // ── edge ───────────────────────────────────────────────────────────

    /// Names differ by case: `Sales` is not `sales`.
    #[test]
    fn names_are_case_sensitive() -> Result<(), TestError> {
        let added = table()?.with_added("Sales", "method == 'INVITE'", &t())?;
        assert_eq!(added.names().count(), 3, "Sales is a new name");
        Ok(())
    }

    /// A quoted `@word` in the definition is a value, not a reference.
    #[test]
    fn a_quoted_at_word_is_not_a_reference() -> Result<(), TestError> {
        let added = table()?.with_added("q", "to.user == '@nosuch'", &t())?;
        assert_eq!(added.expansion("q"), Some("to.user == '@nosuch'"), "kept");
        Ok(())
    }

    /// A refused add leaves nothing behind: the next add of a good name works
    /// on the original table.
    #[test]
    fn a_refused_add_changes_nothing() -> Result<(), TestError> {
        let before = table()?;
        assert!(
            before.with_added("sales", "x == 1", &t()).is_err(),
            "refused"
        );
        assert_eq!(before.names().count(), 2, "still two names");
        Ok(())
    }

    /// Adding two names one after the other keeps both.
    #[test]
    fn two_adds_in_a_row_keep_both() -> Result<(), TestError> {
        let added = table()?
            .with_added("a1", "src.port == 1", &t())?
            .with_added("a2", "src.port == 2", &t())?;
        assert!(
            added.expansion("a1").is_some() && added.expansion("a2").is_some(),
            "both kept"
        );
        Ok(())
    }

    /// The same expression under a second name is allowed.
    #[test]
    fn the_same_expression_under_two_names_is_allowed() -> Result<(), TestError> {
        let added = table()?.with_added("sales2", "to.user == '7000'", &t())?;
        assert_eq!(
            added.expansion("sales2"),
            added.expansion("sales"),
            "same text"
        );
        Ok(())
    }

    /// A multibyte character in a name is refused, not split.
    #[test]
    fn a_multibyte_name_is_refused() -> Result<(), TestError> {
        let err = table()?
            .with_added("caf\u{e9}", "src.port == 1", &t())
            .err();
        assert_eq!(
            err,
            Some(NamedFilterError::BadName("caf\u{e9}".into())),
            "non-ASCII"
        );
        Ok(())
    }

    /// A definition with a multibyte value is kept byte for byte.
    #[test]
    fn a_multibyte_value_is_kept() -> Result<(), TestError> {
        let added = table()?.with_added("cafe", "to.user == 'caf\u{e9}'", &t())?;
        assert_eq!(
            added.definition("cafe"),
            Some("to.user == 'caf\u{e9}'"),
            "kept"
        );
        Ok(())
    }

    /// A definition with surrounding blanks is kept as given; it parses.
    #[test]
    fn a_definition_with_blanks_is_accepted() -> Result<(), TestError> {
        let added = table()?.with_added("sp", "  src.port == 1  ", &t())?;
        assert!(added.expansion("sp").is_some(), "parses with blanks");
        Ok(())
    }

    /// A name that is only digits is accepted.
    #[test]
    fn a_digit_only_name_is_accepted() -> Result<(), TestError> {
        let added = table()?.with_added("5060", "src.port == 5060", &t())?;
        assert!(added.expansion("5060").is_some(), "digits only");
        Ok(())
    }
}

/// [`LiveTable`]: the one table the terminal UI, the REST API and the MCP
/// server of a run read, driven on local instances (the process's own is
/// global, and a test that changed it would change every other test's).
#[cfg(test)]
mod live_tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A table defining each of `names` as `msg_count > 1`.
    fn table(names: &[&str]) -> Result<NamedFilters, TestError> {
        let defs: BTreeMap<String, String> = names
            .iter()
            .map(|n| ((*n).to_owned(), "msg_count > 1".to_owned()))
            .collect();
        Ok(NamedFilters::resolve(&defs, &AliasThresholds::default())?)
    }

    fn names(t: &NamedFilters) -> Vec<String> {
        t.names().map(str::to_owned).collect()
    }

    /// Uninstalled, the table is empty.
    #[test]
    fn an_uninstalled_table_is_empty() {
        let live = LiveTable::new();
        assert!(names(&live.snapshot()).is_empty(), "empty");
    }

    /// The installed table is what a snapshot holds.
    #[test]
    fn install_sets_the_table() -> Result<(), TestError> {
        let live = LiveTable::new();
        assert!(live.install(table(&["big"])?), "first install");
        assert_eq!(names(&live.snapshot()), ["big"], "installed");
        Ok(())
    }

    /// A second install is refused and changes nothing.
    #[test]
    fn a_second_install_changes_nothing() -> Result<(), TestError> {
        let live = LiveTable::new();
        live.install(table(&["big"])?);
        assert!(!live.install(table(&["other"])?), "refused");
        assert_eq!(names(&live.snapshot()), ["big"], "unchanged");
        Ok(())
    }

    /// Publish replaces the table: a later snapshot holds the new name.
    #[test]
    fn publish_replaces_the_table() -> Result<(), TestError> {
        let live = LiveTable::new();
        live.install(table(&["big"])?);
        live.publish(table(&["big", "large"])?);
        assert_eq!(names(&live.snapshot()), ["big", "large"], "published");
        Ok(())
    }

    /// A snapshot taken before a publish keeps the table it was taken from.
    #[test]
    fn an_earlier_snapshot_is_unchanged_by_a_publish() -> Result<(), TestError> {
        let live = LiveTable::new();
        live.install(table(&["big"])?);
        let before = live.snapshot();
        live.publish(table(&["big", "large"])?);
        assert_eq!(names(&before), ["big"], "the old snapshot");
        Ok(())
    }

    /// A publish before any install counts as installed.
    #[test]
    fn publish_before_install_counts_as_installed() -> Result<(), TestError> {
        let live = LiveTable::new();
        live.publish(table(&["large"])?);
        assert!(!live.install(table(&["big"])?), "install refused");
        assert_eq!(names(&live.snapshot()), ["large"], "the published table");
        Ok(())
    }

    /// Two snapshots without a publish share one table.
    #[test]
    fn snapshots_share_the_table() -> Result<(), TestError> {
        let live = LiveTable::new();
        live.install(table(&["big"])?);
        assert!(
            Arc::ptr_eq(&live.snapshot(), &live.snapshot()),
            "one allocation"
        );
        Ok(())
    }

    /// Snapshots taken on other threads see a publish.
    #[test]
    fn other_threads_see_a_publish() -> Result<(), TestError> {
        let live = Arc::new(LiveTable::new());
        live.install(table(&["big"])?);
        live.publish(table(&["big", "large"])?);
        let seen = std::thread::scope(|s| {
            s.spawn(|| names(&live.snapshot()))
                .join()
                .map_err(|_| "the reader thread panicked")
        })?;
        assert_eq!(seen, ["big", "large"], "seen elsewhere");
        Ok(())
    }
}
