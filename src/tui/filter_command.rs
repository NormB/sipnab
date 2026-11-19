// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The filter in force as one `sipnab … --filter '…'` command line, which `Y`
//! in the call list copies.
//!
//! The filter text is the one the call list runs: every F7 field, the named
//! filters expanded, the Expression grouped after them and the After/Before
//! window written as `time` comparisons
//! ([`crate::sip::dsl::FilterExpr::with_time_window`]). Started with that
//! `--filter` on the same capture, a session shows the same call list. Each
//! word is quoted for a POSIX shell.

use std::path::Path;

use crate::sip::dsl::FilterExpr;

/// `word` as one POSIX shell word: as it is when every character is one no
/// shell treats specially, else inside single quotes, each `'` in it written
/// `'\''`.
///
/// Inside single quotes a POSIX shell gives no character a special meaning
/// (`$`, `` ` ``, `\`, `"`, spaces and newlines included), so only the single
/// quote itself needs the close-escape-reopen form.
pub(in crate::tui) fn shell_quote(word: &str) -> String {
    if !word.is_empty() && word.chars().all(is_plain_shell_char) {
        return word.to_owned();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Whether a POSIX shell reads `c` as itself anywhere in a word: ASCII
/// letters, digits and `_ @ % + = : , . / -`. A leading `~` (tilde expansion)
/// and every other punctuation mark are left to the quoted form.
fn is_plain_shell_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c)
}

/// The command line: `sipnab`, the source words, `--filter` and the filter,
/// each word quoted by [`shell_quote`] and joined by one space.
pub(in crate::tui) fn command_line(source: &[String], filter: &str) -> String {
    std::iter::once("sipnab")
        .chain(source.iter().map(String::as_str))
        .chain(["--filter", filter])
        .map(shell_quote)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The words that name the session's capture source.
///
/// # Arguments
/// * `rescan_path` - the one capture file the session reads now, when it
///   reads one (`-I one.pcap`, or the file an in-session open loaded); it
///   wins over `launch`, which an in-session open has replaced.
/// * `launch` - the source words the session was started with: each `-I`
///   input, `--recursive`, `-d` and `-L`, as given.
///
/// # Errors
/// A message when the capture file's path is not valid UTF-8, which a
/// command line copied as text cannot carry unchanged.
pub(in crate::tui) fn command_source(
    rescan_path: Option<&Path>,
    launch: &[String],
) -> Result<Vec<String>, String> {
    match rescan_path {
        None => Ok(launch.to_vec()),
        Some(path) => path
            .to_str()
            .map(|p| vec!["-I".to_owned(), p.to_owned()])
            .ok_or_else(|| {
                format!(
                    "The capture path {} is not valid UTF-8, so a copied command line cannot name it",
                    path.display()
                )
            }),
    }
}

/// The filter text the call list runs: the view filter with the time window
/// ANDed in, as DSL.
///
/// # Returns
/// `None` when neither a view filter nor a time bound is in force.
pub(in crate::tui) fn filter_text(
    active: Option<&FilterExpr>,
    after: Option<chrono::DateTime<chrono::Utc>>,
    before: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<String> {
    FilterExpr::with_time_window(active.cloned(), after, before).map(|f| f.source().to_owned())
}

/// The whole command for the filter in force on `source`.
///
/// # Errors
/// A message for the status line when there is no filter in force, or when
/// the filter holds a NUL character, which no shell word can carry.
pub(in crate::tui) fn filter_command(
    source: &[String],
    filter: Option<&str>,
) -> Result<String, String> {
    let filter =
        filter.ok_or_else(|| "No view filter is in force: apply one with F7 first".to_owned())?;
    if filter.contains('\0') {
        return Err("The filter holds a NUL character, which no shell word can carry".to_owned());
    }
    Ok(command_line(source, filter))
}

/// The words `sh` reads from a command line, for the tests of every module
/// that builds one.
#[cfg(test)]
pub(in crate::tui) mod sh_parse {
    type TestError = Box<dyn std::error::Error>;

    /// The words `sh` reads from `line`, by its own parser.
    ///
    /// `sh` runs `eval "set -- $1"` on the line and prints each positional
    /// parameter followed by a NUL: `set` is a builtin, so the words are
    /// parsed and expanded as a shell would and nothing is run. A quoting
    /// error that let a `$(...)` through would run it, and that is why every
    /// probe below carries only `$(exit 7)`-style payloads that change
    /// nothing. The child runs in a process group of its own and the whole
    /// group is killed at a five-second deadline.
    pub(in crate::tui) fn sh_words(line: &str) -> Result<Vec<String>, TestError> {
        use std::io::Read as _;
        use std::os::unix::process::CommandExt as _;
        let mut child = std::process::Command::new("sh")
            .args([
                "-c",
                "eval \"set -- $1\" || exit 3; for w in \"$@\"; do printf '%s\\0' \"$w\"; done",
                "sh",
                line,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()?;
        let group = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                // The whole group this function created for the child, by
                // the `kill` utility, so a stray `$(...)` that got through
                // goes with it.
                let _ = std::process::Command::new("kill")
                    .args(["-KILL", "--", &format!("-{group}")])
                    .status();
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("sh did not finish within 5 s for {line:?}").into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        let mut out = Vec::new();
        if let Some(mut stdout) = child.stdout.take() {
            stdout.read_to_end(&mut out)?;
        }
        let mut err = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            stderr.read_to_string(&mut err)?;
        }
        if !status.success() {
            return Err(format!("sh refused {line:?}: {status} {err}").into());
        }
        let text = String::from_utf8(out)?;
        let mut words: Vec<String> = text.split('\0').map(str::to_owned).collect();
        // The last NUL ends the last word; the empty piece after it is not one.
        if words.last().is_some_and(String::is_empty) {
            words.pop();
        }
        Ok(words)
    }
}

/// Unit tests for the quoting, the source words and the assembled command;
/// the quoting is proven by handing each command to `sh` itself.
#[cfg(test)]
mod tests {
    use super::sh_parse::sh_words;
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// The texts the round trip hands to `sh`: quotes, spaces, `$`,
    /// backslashes and every other character a shell treats specially.
    const HARD_WORDS: &[&str] = &[
        "plain",
        "two words",
        "it's",
        "''",
        "'",
        "\"double\"",
        "$HOME",
        "${HOME}",
        "$(exit 7)",
        "`exit 7`",
        "back\\slash",
        "\\",
        "\\'",
        "'\\''",
        "tab\there",
        "new\nline",
        "glob*?[a]",
        "~user",
        "semi;exit 7",
        "amp&&exit 7",
        "pipe|exit 7",
        "<redirect>",
        "#comment",
        "!bang",
        "{brace,expansion}",
        "a=b",
        "-I",
        "caf\u{e9} \u{2014} \u{1f4de}",
        "",
        " ",
    ];

    /// `sh` reads each quoted word back as exactly the text it came from.
    #[test]
    fn sh_reads_each_quoted_word_back_unchanged() -> Result<(), TestError> {
        for word in HARD_WORDS {
            let quoted = shell_quote(word);
            assert_eq!(
                sh_words(&quoted)?,
                [word.to_string()],
                "{word:?} quoted as {quoted:?} did not come back whole"
            );
        }
        Ok(())
    }

    /// A whole command of hard words comes back word for word.
    #[test]
    fn sh_reads_a_whole_command_back_word_for_word() -> Result<(), TestError> {
        let source: Vec<String> = vec!["-I".into(), "/cases/it's here/a $b.pcap".into()];
        let filter =
            "payload =~ 'X-Foo' AND NOT payload =~ \"O\\x27K\" AND ua =~ '$(exit 7)`x`\\\\'";
        let line = command_line(&source, filter);
        assert_eq!(
            sh_words(&line)?,
            [
                "sipnab",
                "-I",
                "/cases/it's here/a $b.pcap",
                "--filter",
                filter
            ],
            "the command {line:?} is not the words it was built from"
        );
        Ok(())
    }

    /// A word of safe characters is left as it is.
    #[test]
    fn a_safe_word_is_not_quoted() {
        for word in [
            "sipnab",
            "-I",
            "--filter",
            "/cases/a.pcap",
            "eth0",
            "udp:192.0.2.1:9060",
            "a=b",
            "x@y%z+1,2",
        ] {
            assert_eq!(shell_quote(word), word, "{word} needs no quotes");
        }
    }

    /// An empty word is two single quotes, so it stays a word.
    #[test]
    fn an_empty_word_is_two_quotes() {
        assert_eq!(shell_quote(""), "''", "an empty argument survives");
    }

    /// A single quote is closed, escaped and reopened.
    #[test]
    fn a_single_quote_is_closed_escaped_and_reopened() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'", "the POSIX form");
    }

    /// A space, `$` or backslash puts the word in single quotes.
    #[test]
    fn a_special_character_puts_the_word_in_quotes() {
        assert_eq!(shell_quote("a b"), "'a b'", "space");
        assert_eq!(shell_quote("$x"), "'$x'", "dollar");
        assert_eq!(shell_quote("a\\b"), "'a\\b'", "backslash");
        assert_eq!(shell_quote("~"), "'~'", "a leading tilde would expand");
    }

    /// The command is `sipnab`, the source, `--filter` and the filter.
    #[test]
    fn the_command_names_the_source_and_the_filter() {
        let source: Vec<String> = vec!["-I".into(), "/cases/a.pcap".into()];
        assert_eq!(
            command_line(&source, "msg_count > 5"),
            "sipnab -I /cases/a.pcap --filter 'msg_count > 5'",
            "one ready command"
        );
    }

    /// With no known source the command still carries the filter.
    #[test]
    fn a_command_without_a_source_carries_the_filter() {
        assert_eq!(
            command_line(&[], "method == 'BYE'"),
            "sipnab --filter 'method == '\\''BYE'\\'''",
            "the filter alone"
        );
    }

    /// The one file the session reads now names the source, over the words
    /// the session started with.
    #[test]
    fn the_file_read_now_names_the_source() -> Result<(), TestError> {
        let launch: Vec<String> = vec!["-d".into(), "eth0".into()];
        assert_eq!(
            command_source(Some(Path::new("/cases/opened.pcap")), &launch)?,
            ["-I", "/cases/opened.pcap"],
            "an in-session open replaced the start's source"
        );
        Ok(())
    }

    /// Without one file, the start's source words are kept as given.
    #[test]
    fn without_one_file_the_start_words_are_kept() -> Result<(), TestError> {
        let launch: Vec<String> = ["-I", "a.pcap", "-I", "b.pcap", "--recursive"]
            .map(str::to_owned)
            .to_vec();
        assert_eq!(command_source(None, &launch)?, launch, "as started");
        Ok(())
    }

    /// A capture path that is not UTF-8 is refused: text cannot carry it.
    #[test]
    fn a_path_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStrExt as _;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/cases/\xff.pcap"));
        let err = command_source(Some(path), &[]).err().unwrap_or_default();
        assert!(
            err.contains("not valid UTF-8"),
            "the reason is given: {err:?}"
        );
    }

    /// The filter text is the view filter's own source.
    #[test]
    fn the_filter_text_is_the_view_filters_source() -> Result<(), TestError> {
        let expr = FilterExpr::parse("msg_count > 5")?;
        assert_eq!(
            filter_text(Some(&expr), None, None).as_deref(),
            Some("msg_count > 5"),
            "as compiled"
        );
        Ok(())
    }

    /// The time window joins the filter as `time` comparisons.
    #[test]
    fn the_time_window_joins_as_time_comparisons() -> Result<(), TestError> {
        let expr = FilterExpr::parse("msg_count > 5")?;
        let after = chrono::DateTime::parse_from_rfc3339("2026-07-07T08:00:00Z")?.to_utc();
        let before = chrono::DateTime::parse_from_rfc3339("2026-07-07T09:00:00Z")?.to_utc();
        let text = filter_text(Some(&expr), Some(after), Some(before)).unwrap_or_default();
        assert_eq!(
            text,
            "(msg_count > 5) AND time >= '2026-07-07T08:00:00Z' AND time < '2026-07-07T09:00:00Z'",
            "the window in the DSL"
        );
        FilterExpr::parse(&text)?;
        Ok(())
    }

    /// A time window alone is a filter too.
    #[test]
    fn a_time_window_alone_is_a_filter() -> Result<(), TestError> {
        let after = chrono::DateTime::parse_from_rfc3339("2026-07-07T08:00:00Z")?.to_utc();
        assert_eq!(
            filter_text(None, Some(after), None).as_deref(),
            Some("time >= '2026-07-07T08:00:00Z'"),
            "the lower bound alone"
        );
        Ok(())
    }

    /// No filter and no window: there is no filter text.
    #[test]
    fn nothing_in_force_has_no_filter_text() {
        assert_eq!(filter_text(None, None, None), None, "nothing to copy");
    }

    /// The match-nothing filter of a dialog with every method clear is
    /// copied as the DSL that matches nothing, so the copy shows no calls too.
    #[test]
    fn the_no_methods_filter_is_copied_as_matching_nothing() -> Result<(), TestError> {
        let never = FilterExpr::never();
        let text = filter_text(Some(&never), None, None).unwrap_or_default();
        assert_eq!(
            text, "one_way == true AND one_way == false",
            "matches nothing"
        );
        FilterExpr::parse(&text)?;
        Ok(())
    }

    /// No filter in force: nothing to copy, and the message says how to set one.
    #[test]
    fn no_filter_in_force_is_refused() {
        let err = filter_command(&[], None).err().unwrap_or_default();
        assert!(err.contains("No view filter"), "says why: {err:?}");
        assert!(err.contains("F7"), "says how to set one: {err:?}");
    }

    /// A filter holding a NUL is refused: no shell word can carry one.
    #[test]
    fn a_filter_holding_a_nul_is_refused() {
        let err = filter_command(&[], Some("ua =~ 'a\0b'"))
            .err()
            .unwrap_or_default();
        assert!(err.contains("NUL"), "says why: {err:?}");
    }

    /// The assembled command for a filter in force.
    #[test]
    fn the_command_for_the_filter_in_force() -> Result<(), TestError> {
        let source: Vec<String> = vec!["-I".into(), "a.pcap".into()];
        assert_eq!(
            filter_command(&source, Some("msg_count > 5"))?,
            "sipnab -I a.pcap --filter 'msg_count > 5'",
            "ready to run"
        );
        Ok(())
    }
}
