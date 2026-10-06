// SPDX-License-Identifier: MIT OR Apache-2.0

//! Legacy `%name` placeholders in exec hook templates.
//!
//! `--on-dialog-exec`, `--on-quality-exec` and `--alert-exec` run the
//! operator's template through `sh -c` and pass captured data only as
//! `SIPNAB_*` environment variables. Older templates wrote `%from` where they
//! meant that data; this module rewrites such a placeholder into a reference
//! the shell expands as one word, so captured text can neither add hook
//! arguments nor glob-expand into file names (CWE-78).

/// Rewrite each `%name` in `template` whose name is in `table` to a quoted
/// reference to the environment variable the table pairs it with.
///
/// Each reference is written so `sh -c` expands it as exactly one word with no
/// word splitting and no globbing, whatever quoting surrounds the placeholder:
/// `"${SIPNAB_FROM}"` outside quotes, `${SIPNAB_FROM}` inside double quotes,
/// and `'"${SIPNAB_FROM}"'` inside single quotes, which closes the single
/// quote, expands the value in double quotes, and reopens it. The braces keep
/// text glued to a placeholder (`%from_x`) out of the variable's name.
///
/// The first name in `table` that the text after `%` starts with wins, so no
/// name in a table may be a prefix of another.
pub(crate) fn quote_placeholders(template: &str, table: &[(&str, &str)]) -> String {
    #[derive(Clone, Copy, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }
    let mut out = String::with_capacity(template.len() + 32);
    let mut quote = Quote::None;
    let mut rest = template;
    while let Some(c) = rest.chars().next() {
        if c == '%' {
            let name = &rest[1..];
            if let Some(&(placeholder, var)) = table
                .iter()
                .find(|(placeholder, _)| name.starts_with(placeholder))
            {
                match quote {
                    Quote::None => out.push_str(&format!("\"${{{var}}}\"")),
                    Quote::Double => out.push_str(&format!("${{{var}}}")),
                    Quote::Single => out.push_str(&format!("'\"${{{var}}}\"'")),
                }
                rest = &name[placeholder.len()..];
                continue;
            }
        }
        // A backslash outside single quotes escapes the next character, so an
        // escaped quote does not open or close a quoted span.
        if c == '\\' && quote != Quote::Single {
            let escaped_len = rest[1..].chars().next().map_or(0, char::len_utf8);
            out.push_str(&rest[..1 + escaped_len]);
            rest = &rest[1 + escaped_len..];
            continue;
        }
        quote = match (quote, c) {
            (Quote::None, '\'') => Quote::Single,
            (Quote::None, '"') => Quote::Double,
            (Quote::Single, '\'') | (Quote::Double, '"') => Quote::None,
            (q, _) => q,
        };
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a rewritten `%from` template through `sh -c` the way a hook runs,
    /// with `SIPNAB_FROM` set to `value`, inside a directory holding one file
    /// so an unquoted `*` would visibly glob. Returns stdout.
    fn run_migrated(template: &str, value: &str) -> String {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("glob-would-match-this"), b"").expect("seed file");
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(quote_placeholders(template, &[("from", "SIPNAB_FROM")]))
            .env("SIPNAB_FROM", value)
            .current_dir(dir.path())
            .output()
            .expect("sh should run");
        String::from_utf8(out.stdout).expect("utf-8 stdout")
    }

    /// An operator who already wrapped the placeholder in double quotes gets
    /// the same single argument, not a quote pair that cancels out.
    #[test]
    fn legacy_placeholder_inside_double_quotes_stays_one_argument() {
        let hostile = "a  b *";
        assert_eq!(
            run_migrated("printf '<%s>' \"%from\"", hostile),
            format!("<{hostile}>")
        );
        assert_eq!(
            run_migrated("printf '<%s>' \"from=%from;\"", hostile),
            format!("<from={hostile};>")
        );
    }

    /// Inside single quotes the value still expands. A plain `$SIPNAB_FROM`
    /// there would reach the hook as that literal text, not the value.
    #[test]
    fn legacy_placeholder_inside_single_quotes_expands() {
        let hostile = "a  b *";
        assert_eq!(
            run_migrated("printf '<%s>' 'from=%from;'", hostile),
            format!("<from={hostile};>")
        );
    }

    /// A backslash-escaped quote is a literal character, not the start of a
    /// quoted span, so the placeholder after it is still unquoted context.
    #[test]
    fn legacy_placeholder_after_escaped_quote() {
        assert_eq!(
            run_migrated("printf '<%s>' \\\"%from\\\"", "a  b *"),
            "<\"a  b *\">"
        );
    }

    /// Text glued to a placeholder stays text: `%from_x` is the From value
    /// followed by `_x`, not an unset variable named `SIPNAB_FROM_x`.
    #[test]
    fn legacy_placeholder_followed_by_name_characters() {
        assert_eq!(run_migrated("printf '<%s>' %from_x", "v"), "<v_x>");
    }

    /// Shell syntax inside the value is never run, quoted or not.
    #[test]
    fn legacy_placeholder_value_is_never_executed() {
        let hostile = "$(echo pwned) `echo pwned`; echo pwned";
        assert_eq!(
            run_migrated("printf '<%s>' %from", hostile),
            format!("<{hostile}>")
        );
    }
}
