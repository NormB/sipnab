// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! One rule: under `pipefail`, no pipe feeds a reader that can stop reading
//! before its writer is done.
//!
//! `grep -q` exits at its first match, `head` after its count, `awk` at
//! `exit`, `sed` at `q`, `read` after one line. If the command writing into
//! the pipe still has output, its next write gets SIGPIPE and it dies with
//! status 141. Without `pipefail` nobody sees that status. With it, the
//! pipeline fails although the reader found what it looked for. The race is
//! lost rarely when the writer has less to say than a pipe holds (measured
//! 2026-11-02: one run in 2400 on a loaded host) and every time when it has
//! more.
//!
//! The safe forms have no writer process to kill: a here-string
//! (`grep -q x <<<"$out"`), a file operand (`grep -q x file`), or a reader
//! that reads to the end (`sed -n 1p` for `head -1`, `awk` with a flag
//! instead of `exit`, `grep` without `-q`/`-m`/`-l`/`-L`).
//!
//! `tests/pipefail_early_exit_test.rs` is the gate that runs this over every
//! tracked shell file, git hook and workflow `run:` block, and holds the
//! matcher to its cases. There is no automatic fixer: every site was changed
//! by hand, and this file is the rule both the gate and the per-script tests
//! (`tests/split_debuginfo_test.rs`, `tests/private_identity_test.rs`) apply.
//!
//! What the scanner reads:
//!
//! * shell text with its quoting, comments, `\` continuations, here-documents
//!   (an unquoted body's `$( )` is code, a quoted body is data), `$( )`,
//!   backticks, `<( )`, `${ }`, `$(( ))`, `(( ))`, `[[ ]]`, `case` patterns
//!   and `name=( )` arrays, so a `|` that is not a pipe is never taken for
//!   one;
//! * the pipefail state: `set -o pipefail`/`+o`, option clusters such as
//!   `-euo`, `shopt -so`, a shebang carrying it, a `( )` or `$( )` subshell
//!   that changes it without leaking, and `bash -c '...'` strings with their
//!   own options. A file with no shebang is a sourced library and is read as
//!   pipefail, because the scripts that source this repository's libraries set
//!   it;
//! * workflow and composite-action `run:` blocks with GitHub's shell rules: a
//!   step with no `shell:` runs as `bash -e {0}` (no pipefail), `shell: bash`
//!   as `bash --noprofile --norc -eo pipefail {0}`, `sh` as `sh -e {0}`, and a
//!   custom `{0}` command by its own options. A `defaults:` block or a Windows
//!   runner is refused rather than guessed.
//!
//! What it does not read: `[[ ]]` and `(( ))` contents (no command runs
//! there), `sed -f`/`awk -f` program files (a file operand is read as no
//! quit), and readers it does not know. Plain `grep >/dev/null` and `grep -c`
//! are not flagged: GNU grep 3.11 reads to the end for both (measured), but
//! ugrep 7.8.4 does not, so the sweep's own fixes never rely on them.
#![allow(dead_code)]

/// One pipe into a reader that can stop before its writer is done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// 1-based line of the reader in the scanned text.
    pub line: usize,
    /// The reader and the option that makes it stop early, e.g. `grep -q`.
    pub reader: String,
}

// ---------------------------------------------------------------------------
// The predicate: which commands stop reading early.
// ---------------------------------------------------------------------------

/// The reader `words` runs, when that reader can exit before reading all of
/// its standard input, or `None`.
///
/// `words` is one simple command, dequoted. Leading assignments and the
/// wrappers `command`, `builtin`, `exec`, `env`, `nice`, `nohup`, `stdbuf`,
/// `timeout` and `sudo` are stepped over.
pub fn early_exit_reader(words: &[&str]) -> Option<String> {
    let w = strip_wrappers(words);
    let (name, args) = w.split_first()?;
    let base = name.rsplit('/').next().unwrap_or(name);
    match base {
        "grep" | "egrep" | "fgrep" | "zgrep" | "zegrep" | "zfgrep" => {
            grep_early_option(args).map(|o| format!("grep {o}"))
        }
        "head" => (!head_reads_all(args)).then(|| "head".to_owned()),
        "sed" | "gsed" => sed_quits(args).then(|| "sed q".to_owned()),
        "awk" | "gawk" | "mawk" | "nawk" => awk_exits_early(args).then(|| "awk exit".to_owned()),
        "read" => Some("read".to_owned()),
        "mapfile" | "readarray" => args
            .windows(2)
            .any(|p| p[0] == "-n" && p[1] != "0")
            .then(|| "mapfile -n".to_owned()),
        "cmp" => Some("cmp".to_owned()),
        "dd" => args
            .iter()
            .any(|a| a.starts_with("count="))
            .then(|| "dd count=".to_owned()),
        "true" | "false" | ":" => Some(format!("{base} (reads nothing)")),
        _ => None,
    }
}

fn is_assignment(w: &str) -> bool {
    let Some(eq) = w.find('=') else {
        return false;
    };
    let name = w[..eq].trim_end_matches('+');
    let name = name.split('[').next().unwrap_or(name);
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `words` without leading assignments and command wrappers.
fn strip_wrappers<'a, 'b>(mut w: &'b [&'a str]) -> &'b [&'a str] {
    loop {
        while w.first().is_some_and(|x| is_assignment(x)) {
            w = &w[1..];
        }
        let Some(first) = w.first() else {
            return w;
        };
        let base = first.rsplit('/').next().unwrap_or(first);
        // Options of each wrapper that take a separate argument.
        let with_arg: &[&str] = match base {
            "command" | "builtin" | "nohup" => &[],
            "exec" => &["-a"],
            "env" => &["-u", "-C", "-S", "--unset", "--chdir"],
            "nice" => &["-n", "--adjustment"],
            "stdbuf" => &["-i", "-o", "-e"],
            "timeout" => &["-s", "-k", "--signal", "--kill-after"],
            "sudo" => &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"],
            _ => return w,
        };
        w = &w[1..];
        while let Some(o) = w.first() {
            if *o == "--" {
                w = &w[1..];
                break;
            }
            if !o.starts_with('-') || *o == "-" {
                break;
            }
            w = &w[1..];
            if with_arg.contains(o) {
                w = w.get(1..).unwrap_or(&[]);
            }
        }
        if base == "env" {
            while w.first().is_some_and(|x| is_assignment(x)) {
                w = &w[1..];
            }
        }
        if base == "timeout" && !w.is_empty() {
            w = &w[1..]; // the duration
        }
    }
}

/// The grep option that makes it stop at a match, if any.
fn grep_early_option(args: &[&str]) -> Option<String> {
    const LONG_EARLY: &[&str] = &[
        "--quiet",
        "--silent",
        "--files-with-matches",
        "--files-without-match",
        "--max-count",
    ];
    const LONG_ARG: &[&str] = &[
        "--regexp",
        "--file",
        "--max-count",
        "--after-context",
        "--before-context",
        "--context",
        "--devices",
        "--directories",
        "--binary-files",
        "--label",
        "--include",
        "--exclude",
        "--exclude-from",
        "--exclude-dir",
        "--group-separator",
    ];
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        i += 1;
        if a == "--" {
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let name = format!("--{}", long.split('=').next().unwrap_or(long));
            if LONG_EARLY.contains(&name.as_str()) {
                return Some(name);
            }
            if LONG_ARG.contains(&name.as_str()) && !a.contains('=') {
                i += 1;
            }
            continue;
        }
        let Some(cluster) = a.strip_prefix('-') else {
            continue;
        };
        for (k, c) in cluster.char_indices() {
            match c {
                'q' | 'l' | 'L' => return Some(format!("-{c}")),
                'm' => return Some("-m".to_owned()),
                'e' | 'f' | 'A' | 'B' | 'C' | 'D' | 'd' => {
                    if k + 1 == cluster.len() {
                        i += 1; // the argument is the next word
                    }
                    break; // the rest of the cluster is the argument
                }
                _ => {}
            }
        }
    }
    None
}

/// `head` reads its whole input only with a negative count ("all but the
/// last N").
fn head_reads_all(args: &[&str]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        i += 1;
        let value = if a == "-n" || a == "-c" || a == "--lines" || a == "--bytes" {
            let v = args.get(i).copied().unwrap_or("");
            i += 1;
            v
        } else if let Some(v) = a
            .strip_prefix("--lines=")
            .or_else(|| a.strip_prefix("--bytes="))
        {
            v
        } else if let Some(v) = a.strip_prefix("-n").or_else(|| a.strip_prefix("-c")) {
            v
        } else {
            continue;
        };
        if value.starts_with('-') {
            return true;
        }
    }
    false
}

/// Whether any `sed` script among `args` has a `q` or `Q` command.
fn sed_quits(args: &[&str]) -> bool {
    let mut scripts = Vec::new();
    let mut explicit = false;
    let mut first_operand = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        i += 1;
        if a == "--" {
            if first_operand.is_none() {
                first_operand = args.get(i).copied();
            }
            break;
        }
        if a == "-e" || a == "--expression" {
            explicit = true;
            if let Some(s) = args.get(i) {
                scripts.push(*s);
            }
            i += 1;
        } else if let Some(s) = a.strip_prefix("--expression=") {
            explicit = true;
            scripts.push(s);
        } else if a == "-f" || a == "--file" || a == "-l" || a == "--line-length" {
            explicit |= a == "-f" || a == "--file";
            i += 1;
        } else if a.starts_with("--") {
        } else if let Some(cluster) = a.strip_prefix('-').filter(|c| !c.is_empty()) {
            if let Some(p) = cluster.find('e') {
                explicit = true;
                let rest = &cluster[p + 1..];
                if rest.is_empty() {
                    if let Some(s) = args.get(i) {
                        scripts.push(*s);
                    }
                    i += 1;
                } else {
                    scripts.push(rest);
                }
            } else if cluster.ends_with('f') {
                explicit = true;
                i += 1;
            }
        } else if first_operand.is_none() {
            first_operand = Some(a);
        }
    }
    if !explicit {
        scripts.extend(first_operand);
    }
    scripts.iter().any(|s| sed_script_quits(s))
}

/// Whether a sed script has a `q` or `Q` command, read command by command so
/// that a `q` inside an address, an `s` or a `y` is not one.
fn sed_script_quits(script: &str) -> bool {
    let c: Vec<char> = script.chars().collect();
    let mut i = 0;
    let skip_delimited = |i: &mut usize, delim: char| {
        while *i < c.len() && c[*i] != delim {
            if c[*i] == '\\' {
                *i += 1;
            }
            *i += 1;
        }
        *i += 1;
    };
    let to_eol = |i: &mut usize| {
        while *i < c.len() && c[*i] != '\n' {
            *i += 1;
        }
    };
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() || ch == ';' || ch == '}' || ch == '{' || ch == '!' {
            i += 1;
            continue;
        }
        // Address: line numbers, `$`, `/re/`, `\cREc`, `first~step`, `+N`, `,`.
        if ch.is_ascii_digit() || ch == '$' || ch == ',' || ch == '~' || ch == '+' {
            i += 1;
            continue;
        }
        if ch == '/' {
            i += 1;
            skip_delimited(&mut i, '/');
            while i < c.len() && (c[i] == 'I' || c[i] == 'M') {
                i += 1;
            }
            continue;
        }
        if ch == '\\' && i + 1 < c.len() {
            let d = c[i + 1];
            i += 2;
            skip_delimited(&mut i, d);
            while i < c.len() && (c[i] == 'I' || c[i] == 'M') {
                i += 1;
            }
            continue;
        }
        i += 1;
        match ch {
            'q' | 'Q' => return true,
            's' | 'y' => {
                if i < c.len() {
                    let d = c[i];
                    i += 1;
                    skip_delimited(&mut i, d);
                    skip_delimited(&mut i, d);
                }
                // Flags, up to `;`, `}` or a newline; `w file` takes the line.
                while i < c.len() && !matches!(c[i], ';' | '}' | '\n') {
                    if c[i] == 'w' {
                        to_eol(&mut i);
                        break;
                    }
                    i += 1;
                }
            }
            'a' | 'i' | 'c' | 'r' | 'R' | 'w' | 'W' | 'e' | '#' => to_eol(&mut i),
            ':' | 'b' | 't' | 'T' => {
                while i < c.len() && !matches!(c[i], ';' | '\n') {
                    i += 1;
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether the awk program among `args` can exit before reading all input:
/// `exit` or `nextfile` anywhere but an `END` (or `ENDFILE`) action.
fn awk_exits_early(args: &[&str]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        i += 1;
        match a {
            "-F" | "-v" | "--field-separator" | "--assign" => i += 1,
            "-f" | "--file" => return false, // program in a file: not read
            "--" => return args.get(i).is_some_and(|p| awk_program_exits_early(p)),
            _ if a.starts_with('-') && a.len() > 1 => {}
            _ => return awk_program_exits_early(a),
        }
    }
    false
}

#[derive(Debug, PartialEq)]
enum AwkTok {
    Ident(String),
    Open,
    Close,
    Other(char),
    Newline,
}

fn awk_tokens(prog: &str) -> Vec<AwkTok> {
    let c: Vec<char> = prog.chars().collect();
    let mut out: Vec<AwkTok> = Vec::new();
    let mut i = 0;
    let regex_allowed = |out: &[AwkTok]| match out.last() {
        None | Some(AwkTok::Newline | AwkTok::Open | AwkTok::Close) => true,
        Some(AwkTok::Other(p)) => "(,;!~&|?:=<>+-*%^[".contains(*p),
        Some(AwkTok::Ident(w)) => matches!(w.as_str(), "print" | "printf" | "return" | "in"),
    };
    while i < c.len() {
        let ch = c[i];
        match ch {
            '#' => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '\n' => {
                out.push(AwkTok::Newline);
                i += 1;
            }
            '"' => {
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                out.push(AwkTok::Other('"'));
            }
            '/' if regex_allowed(&out) => {
                i += 1;
                let mut in_class = false;
                while i < c.len() && (c[i] != '/' || in_class) {
                    match c[i] {
                        '\\' => i += 1,
                        '[' => in_class = true,
                        ']' => in_class = false,
                        _ => {}
                    }
                    i += 1;
                }
                i += 1;
                out.push(AwkTok::Other('r'));
            }
            '{' => {
                out.push(AwkTok::Open);
                i += 1;
            }
            '}' => {
                out.push(AwkTok::Close);
                i += 1;
            }
            _ if ch.is_ascii_alphabetic() || ch == '_' => {
                let start = i;
                while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
                    i += 1;
                }
                out.push(AwkTok::Ident(c[start..i].iter().collect()));
            }
            _ if ch.is_ascii_digit() => {
                while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '.') {
                    i += 1;
                }
                out.push(AwkTok::Ident(String::new()));
            }
            _ if ch.is_whitespace() => i += 1,
            _ => {
                out.push(AwkTok::Other(ch));
                i += 1;
            }
        }
    }
    out
}

fn awk_program_exits_early(prog: &str) -> bool {
    let toks = awk_tokens(prog);
    let mut i = 0;
    // The first word of the current top-level item's pattern.
    let mut head: Option<String> = None;
    while i < toks.len() {
        match &toks[i] {
            AwkTok::Open => {
                let ends = matches!(head.as_deref(), Some("END" | "ENDFILE"));
                let mut depth = 0usize;
                let mut early = false;
                while i < toks.len() {
                    match &toks[i] {
                        AwkTok::Open => depth += 1,
                        AwkTok::Close => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        AwkTok::Ident(w) if w == "exit" || w == "nextfile" => early = true,
                        _ => {}
                    }
                    i += 1;
                }
                if early && !ends {
                    return true;
                }
                head = None;
            }
            AwkTok::Newline | AwkTok::Other(';') => head = None,
            AwkTok::Ident(w) if head.is_none() => head = Some(w.clone()),
            t => {
                if head.is_none() {
                    head = Some(format!("{t:?}"));
                }
            }
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// The lexer: shell text to tokens, with nested code split out.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Word {
    /// Dequoted text; an expansion stays as written (`$x`, `$(…)`).
    text: String,
    /// 1-based line the word starts on.
    line: usize,
    /// No expansion and no substitution anywhere in the word.
    literal: bool,
}

#[derive(Debug, Clone)]
enum Tok {
    Word(Word),
    /// `|` `|&` `||` `&&` `;` `&` `;;` `;&` `;;&` `(` `)` and `\n`.
    Op(&'static str),
    /// A redirection whose target is the next word.
    Redir,
    /// A `case` pattern, up to and including its `)`.
    Pattern,
    /// Code that runs in a subshell: `$( )`, backticks, `<( )`, `>( )`, or a
    /// substitution in an unquoted here-document. `line` is where it starts.
    Sub {
        text: String,
        line: usize,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum Case {
    Subject,
    InKeyword,
    Pattern,
    Body,
}

struct Heredoc {
    delim: String,
    strip_tabs: bool,
    quoted: bool,
}

struct Lexer<'a> {
    s: &'a [char],
    i: usize,
    line: usize,
    toks: Vec<Tok>,
    pending: Vec<Heredoc>,
    cmd_start: bool,
    case: Vec<Case>,
    depth: usize,
    expect_target: bool,
}

const RESERVED_PREFIX: &[&str] = &[
    "if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time", "fi", "done",
    "esac",
];

impl<'a> Lexer<'a> {
    fn new(s: &'a [char], i: usize, line: usize) -> Self {
        Lexer {
            s,
            i,
            line,
            toks: Vec::new(),
            pending: Vec::new(),
            cmd_start: true,
            case: Vec::new(),
            depth: 0,
            expect_target: false,
        }
    }

    fn peek(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }

    fn starts(&self, pat: &str) -> bool {
        pat.chars()
            .enumerate()
            .all(|(k, c)| self.peek(k) == Some(c))
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.i += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    /// Lex until the end of input, or, with `until_paren`, past the `)` that
    /// closes the substitution the lexer started in.
    fn run(&mut self, until_paren: bool) {
        loop {
            while matches!(self.peek(0), Some(' ' | '\t' | '\r')) {
                self.i += 1;
            }
            let Some(c) = self.peek(0) else { break };
            if c == '\\' && self.peek(1) == Some('\n') {
                self.bump();
                self.bump();
                continue;
            }
            if c == '#' {
                while self.peek(0).is_some_and(|c| c != '\n') {
                    self.i += 1;
                }
                continue;
            }
            if c == '\n' {
                self.bump();
                self.toks.push(Tok::Op("\n"));
                self.cmd_start = true;
                self.read_heredoc_bodies();
                continue;
            }
            if self.case.last() == Some(&Case::Pattern) {
                if self.word_ahead("esac") {
                    self.i += 4;
                    self.case.pop();
                    self.toks.push(Tok::Word(Word {
                        text: "esac".into(),
                        line: self.line,
                        literal: true,
                    }));
                    self.cmd_start = false;
                } else {
                    self.read_pattern();
                }
                continue;
            }
            if let Some(op) = self.read_op() {
                match op {
                    "(" => self.depth += 1,
                    ")" => {
                        if self.depth == 0 && until_paren {
                            return;
                        }
                        self.depth = self.depth.saturating_sub(1);
                    }
                    ";;" | ";&" | ";;&" => {
                        if let Some(top) = self.case.last_mut() {
                            *top = Case::Pattern;
                        }
                    }
                    _ => {}
                }
                if op != "redir" {
                    self.toks.push(Tok::Op(op));
                    self.cmd_start = true;
                }
                continue;
            }
            if self.cmd_start && (self.word_ahead("[[") || self.starts("((")) {
                self.skip_opaque();
                continue;
            }
            let line = self.line;
            let Some((w, _quoted)) = self.read_word() else {
                continue;
            };
            if self.expect_target {
                self.expect_target = false;
                self.toks.push(Tok::Word(Word {
                    text: w.text,
                    line,
                    literal: w.literal,
                }));
                continue;
            }
            if w.text.chars().all(|c| c.is_ascii_digit()) && matches!(self.peek(0), Some('<' | '>'))
            {
                continue; // a file descriptor number
            }
            self.case_word(&w.text);
            let prefix = self.cmd_start
                && (RESERVED_PREFIX.contains(&w.text.as_str()) || is_assignment(&w.text));
            self.cmd_start = prefix;
            self.toks.push(Tok::Word(Word { line, ..w }));
        }
    }

    fn case_word(&mut self, text: &str) {
        match self.case.last().copied() {
            Some(Case::Subject) => {
                if let Some(t) = self.case.last_mut() {
                    *t = Case::InKeyword;
                }
            }
            Some(Case::InKeyword) if text == "in" => {
                if let Some(t) = self.case.last_mut() {
                    *t = Case::Pattern;
                }
            }
            Some(Case::Body) if self.cmd_start && text == "esac" => {
                self.case.pop();
            }
            _ => {
                if self.cmd_start && text == "case" {
                    self.case.push(Case::Subject);
                }
            }
        }
    }

    /// Whether `w` comes next as a whole word.
    fn word_ahead(&self, w: &str) -> bool {
        self.starts(w)
            && self
                .peek(w.chars().count())
                .is_none_or(|c| c.is_whitespace() || ";&|()".contains(c))
    }

    /// Step over `[[ … ]]` or `(( … ))`, where no command runs.
    fn skip_opaque(&mut self) {
        let line = self.line;
        let closing = if self.starts("((") { "))" } else { "]]" };
        self.i += 2;
        let mut depth = 0i32;
        while let Some(c) = self.peek(0) {
            if closing == "))" {
                if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    if depth == 0 && self.peek(1) == Some(')') {
                        self.i += 2;
                        break;
                    }
                    depth -= 1;
                }
            } else if self.word_ahead("]]")
                && self
                    .s
                    .get(self.i.wrapping_sub(1))
                    .is_some_and(|p| p.is_whitespace())
            {
                self.i += 2;
                break;
            }
            match c {
                '\'' => {
                    self.bump();
                    while self.peek(0).is_some_and(|c| c != '\'') {
                        self.bump();
                    }
                    self.bump();
                }
                '"' => {
                    self.bump();
                    let mut w = String::new();
                    let mut lit = true;
                    self.read_dquote(&mut w, &mut lit, Some('"'));
                }
                '\\' => {
                    self.bump();
                    self.bump();
                }
                '$' => {
                    let mut w = String::new();
                    let mut lit = true;
                    self.read_dollar(&mut w, &mut lit);
                }
                _ => {
                    self.bump();
                }
            }
        }
        self.toks.push(Tok::Word(Word {
            text: "[[…]]".into(),
            line,
            literal: false,
        }));
        self.cmd_start = false;
    }

    /// A `case` pattern: everything up to the unquoted `)` at depth 0.
    fn read_pattern(&mut self) {
        let mut depth = 0i32;
        if self.peek(0) == Some('(') {
            self.i += 1;
        }
        while let Some(c) = self.peek(0) {
            match c {
                '(' => depth += 1,
                ')' if depth == 0 => {
                    self.i += 1;
                    break;
                }
                ')' => depth -= 1,
                '\\' => {
                    self.bump();
                }
                '\'' => {
                    self.bump();
                    while self.peek(0).is_some_and(|c| c != '\'') {
                        self.bump();
                    }
                }
                '"' => {
                    self.bump();
                    let mut w = String::new();
                    let mut lit = true;
                    self.read_dquote(&mut w, &mut lit, Some('"'));
                    continue;
                }
                _ => {}
            }
            self.bump();
        }
        self.toks.push(Tok::Pattern);
        if let Some(t) = self.case.last_mut() {
            *t = Case::Body;
        }
        self.cmd_start = true;
    }

    fn read_op(&mut self) -> Option<&'static str> {
        const OPS: &[&str] = &[
            ";;&", "&>>", "<<<", "<<-", "|&", "||", "&&", ";;", ";&", "&>", "<<", "<>", "<&", ">>",
            ">&", ">|", "|", ";", "&", "(", ")", "<", ">",
        ];
        // `<(` and `>(` start a process substitution, read as a word.
        if matches!(self.peek(0), Some('<' | '>')) && self.peek(1) == Some('(') {
            return None;
        }
        let op = *OPS.iter().find(|o| self.starts(o))?;
        if op == "(" && self.cmd_start && self.starts("((") {
            return None; // arithmetic command, skipped as opaque
        }
        self.i += op.len();
        match op {
            "<<" | "<<-" => {
                self.read_heredoc_delim(op == "<<-");
                Some("redir")
            }
            "&>>" | "<<<" | "&>" | "<>" | "<&" | ">>" | ">&" | ">|" | "<" | ">" => {
                self.expect_target = true;
                self.toks.push(Tok::Redir);
                Some("redir")
            }
            _ => Some(op),
        }
    }

    fn read_heredoc_delim(&mut self, strip_tabs: bool) {
        while matches!(self.peek(0), Some(' ' | '\t')) {
            self.i += 1;
        }
        if let Some((w, quoted)) = self.read_word() {
            self.pending.push(Heredoc {
                delim: w.text,
                strip_tabs,
                quoted,
            });
        }
    }

    fn read_heredoc_bodies(&mut self) {
        let docs = std::mem::take(&mut self.pending);
        for doc in docs {
            let mut body = String::new();
            let body_line = self.line;
            loop {
                if self.peek(0).is_none() {
                    break;
                }
                let mut l = String::new();
                while let Some(c) = self.peek(0) {
                    self.bump();
                    if c == '\n' {
                        break;
                    }
                    l.push(c);
                }
                let cmp = if doc.strip_tabs {
                    l.trim_start_matches('\t')
                } else {
                    l.as_str()
                };
                if cmp == doc.delim {
                    break;
                }
                body.push_str(&l);
                body.push('\n');
            }
            if !doc.quoted {
                let chars: Vec<char> = body.chars().collect();
                let mut sub = Lexer::new(&chars, 0, body_line);
                let mut w = String::new();
                let mut lit = true;
                sub.read_dquote(&mut w, &mut lit, None);
                self.toks.append(&mut sub.toks);
            }
        }
    }

    /// One word. Returns `None` when there is no word here (a comment).
    fn read_word(&mut self) -> Option<(Word, bool)> {
        let line = self.line;
        let mut text = String::new();
        let mut literal = true;
        let mut quoted = false;
        while let Some(c) = self.peek(0) {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | ')' => break,
                '<' | '>' if self.peek(1) == Some('(') => {
                    self.i += 2;
                    self.read_sub_paren();
                    text.push_str("<(…)");
                    literal = false;
                }
                '<' | '>' => break,
                '(' => {
                    let extglob = text.ends_with(['@', '!', '+', '*', '?']);
                    if is_assignment(&text) && text.ends_with('=') || extglob {
                        self.read_balanced_into(&mut text, &mut literal);
                    } else {
                        break;
                    }
                }
                '#' if text.is_empty() => {
                    while self.peek(0).is_some_and(|c| c != '\n') {
                        self.i += 1;
                    }
                    return None;
                }
                '\\' => {
                    quoted = true;
                    self.bump();
                    match self.bump() {
                        Some('\n') | None => {}
                        Some(n) => text.push(n),
                    }
                }
                '\'' => {
                    quoted = true;
                    self.bump();
                    while let Some(c) = self.bump() {
                        if c == '\'' {
                            break;
                        }
                        text.push(c);
                    }
                }
                '$' if self.peek(1) == Some('\'') => {
                    quoted = true;
                    self.i += 2;
                    while let Some(c) = self.bump() {
                        if c == '\'' {
                            break;
                        }
                        if c == '\\' {
                            if let Some(n) = self.bump() {
                                text.push('\\');
                                text.push(n);
                            }
                            continue;
                        }
                        text.push(c);
                    }
                }
                '"' => {
                    quoted = true;
                    self.bump();
                    self.read_dquote(&mut text, &mut literal, Some('"'));
                }
                '$' => self.read_dollar(&mut text, &mut literal),
                '`' => {
                    self.bump();
                    self.read_backtick();
                    text.push_str("`…`");
                    literal = false;
                }
                _ => {
                    self.bump();
                    text.push(c);
                }
            }
        }
        if text.is_empty() && !quoted {
            // Nothing consumed: a lone character the caller did not expect.
            if self.peek(0).is_some_and(|c| c == '<' || c == '>') {
                return None;
            }
        }
        Some((
            Word {
                text,
                line,
                literal,
            },
            quoted,
        ))
    }

    /// `name=( … )` or an extended glob `@( … )`: kept inside the word.
    fn read_balanced_into(&mut self, text: &mut String, literal: &mut bool) {
        let mut depth = 0i32;
        while let Some(c) = self.peek(0) {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        self.bump();
                        text.push(')');
                        return;
                    }
                }
                '\'' => {
                    self.bump();
                    while let Some(c) = self.bump() {
                        if c == '\'' {
                            break;
                        }
                        text.push(c);
                    }
                    continue;
                }
                '"' => {
                    self.bump();
                    self.read_dquote(text, literal, Some('"'));
                    continue;
                }
                '$' => {
                    self.read_dollar(text, literal);
                    continue;
                }
                '\\' => {
                    self.bump();
                }
                _ => {}
            }
            if let Some(c) = self.bump() {
                text.push(c);
            }
        }
    }

    /// Inside double quotes (or an unquoted here-document body, `end` None).
    fn read_dquote(&mut self, text: &mut String, literal: &mut bool, end: Option<char>) {
        while let Some(c) = self.peek(0) {
            if Some(c) == end {
                self.bump();
                return;
            }
            match c {
                '\\' => {
                    self.bump();
                    match self.peek(0) {
                        Some('\n') => {
                            self.bump();
                        }
                        Some(n @ ('$' | '`' | '"' | '\\')) => {
                            self.bump();
                            text.push(n);
                        }
                        _ => text.push('\\'),
                    }
                }
                '$' => self.read_dollar(text, literal),
                '`' => {
                    self.bump();
                    self.read_backtick();
                    text.push_str("`…`");
                    *literal = false;
                }
                _ => {
                    self.bump();
                    text.push(c);
                }
            }
        }
    }

    fn read_dollar(&mut self, text: &mut String, literal: &mut bool) {
        self.bump(); // `$`
        match self.peek(0) {
            Some('(') if self.peek(1) == Some('(') => {
                self.i += 2;
                let mut depth = 2i32;
                while let Some(c) = self.bump() {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                text.push_str("$((…))");
                *literal = false;
            }
            Some('(') => {
                self.i += 1;
                self.read_sub_paren();
                text.push_str("$(…)");
                *literal = false;
            }
            Some('{') => {
                self.bump();
                let mut depth = 1i32;
                while let Some(c) = self.peek(0) {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                self.bump();
                                break;
                            }
                        }
                        '\\' => {
                            self.bump();
                        }
                        '\'' => {
                            self.bump();
                            while self.peek(0).is_some_and(|c| c != '\'') {
                                self.bump();
                            }
                        }
                        '"' => {
                            self.bump();
                            let mut w = String::new();
                            self.read_dquote(&mut w, literal, Some('"'));
                            continue;
                        }
                        '$' => {
                            let mut w = String::new();
                            self.read_dollar(&mut w, literal);
                            continue;
                        }
                        _ => {}
                    }
                    self.bump();
                }
                text.push_str("${…}");
                *literal = false;
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                text.push('$');
                while let Some(c) = self
                    .peek(0)
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    self.bump();
                    text.push(c);
                }
                *literal = false;
            }
            Some(c) if c.is_ascii_digit() || "@*#?$!-".contains(c) => {
                self.bump();
                text.push('$');
                text.push(c);
                *literal = false;
            }
            _ => text.push('$'),
        }
    }

    /// After `$(`, `<(` or `>(`: lex the code to its closing `)` and keep it
    /// as a nested script.
    fn read_sub_paren(&mut self) {
        let start = self.i;
        let line = self.line;
        let mut inner = Lexer::new(self.s, self.i, self.line);
        inner.run(true);
        let end = inner.i.saturating_sub(1).max(start);
        self.i = inner.i;
        self.line = inner.line;
        let text: String = self.s[start..end.min(self.s.len())].iter().collect();
        self.toks.push(Tok::Sub { text, line });
    }

    fn read_backtick(&mut self) {
        let line = self.line;
        let mut text = String::new();
        while let Some(c) = self.bump() {
            match c {
                '`' => break,
                '\\' => match self.bump() {
                    Some(n @ ('`' | '$' | '\\')) => text.push(n),
                    Some(n) => {
                        text.push('\\');
                        text.push(n);
                    }
                    None => {}
                },
                _ => text.push(c),
            }
        }
        self.toks.push(Tok::Sub { text, line });
    }
}

fn lex(text: &str, line: usize) -> Vec<Tok> {
    let chars: Vec<char> = text.chars().collect();
    let mut l = Lexer::new(&chars, 0, line);
    l.run(false);
    l.toks
}

// ---------------------------------------------------------------------------
// The scanner: tokens to findings, with the pipefail state.
// ---------------------------------------------------------------------------

struct Loop {
    consumer: bool,
    line: usize,
    early: bool,
}

/// Findings in shell `text`, read with `pipefail` already on or off.
pub fn scan_shell(text: &str, pipefail: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    scan_at(text, 1, pipefail, &mut out);
    out.sort_by_key(|f| f.line);
    out.dedup();
    out
}

/// Findings in a whole shell file. A file without a shebang is a sourced
/// library and is read as pipefail; one with a shebang starts as its
/// interpreter's options say.
pub fn scan_shell_file(text: &str) -> Vec<Finding> {
    let first = text.lines().next().unwrap_or("");
    let pipefail = match first.strip_prefix("#!") {
        None => true,
        Some(shebang) => shebang.contains("pipefail"),
    };
    scan_shell(text, pipefail)
}

fn scan_at(text: &str, line: usize, pipefail: bool, out: &mut Vec<Finding>) {
    let toks = lex(text, line);
    let mut pf = pipefail;
    let mut parens: Vec<bool> = Vec::new();
    let mut loops: Vec<Loop> = Vec::new();
    let mut cur: Vec<Word> = Vec::new();
    let mut consumer = false;
    let mut skip_target = false;
    let mut header = false; // inside `for … in …` or `case … in`, up to `do`/`in`

    for tok in toks {
        match tok {
            Tok::Sub { text, line } => scan_at(&text, line, pf, out),
            Tok::Redir => skip_target = true,
            Tok::Word(w) => {
                if skip_target {
                    skip_target = false;
                    continue;
                }
                if header {
                    if w.text == "do" || w.text == "in" {
                        header = false;
                    }
                    continue;
                }
                if cur.is_empty() {
                    match w.text.as_str() {
                        "while" | "until" => {
                            loops.push(Loop {
                                consumer,
                                line: w.line,
                                early: false,
                            });
                            consumer = false;
                            continue;
                        }
                        "for" | "select" => {
                            loops.push(Loop {
                                consumer: false,
                                line: w.line,
                                early: false,
                            });
                            consumer = false;
                            header = true;
                            continue;
                        }
                        "case" => {
                            header = true;
                            continue;
                        }
                        "done" => {
                            if let Some(l) = loops.pop()
                                && l.consumer
                                && l.early
                            {
                                out.push(Finding {
                                    line: l.line,
                                    reader: "while read … break".into(),
                                });
                            }
                            continue;
                        }
                        "function" => {
                            header = false;
                            cur.push(w);
                            continue;
                        }
                        t if RESERVED_PREFIX.contains(&t) => continue,
                        _ => {}
                    }
                }
                cur.push(w);
            }
            Tok::Op(op) => {
                end_command(&mut cur, &mut consumer, &mut pf, &mut loops, out);
                match op {
                    "|" | "|&" => consumer = true,
                    "(" => parens.push(pf),
                    ")" => pf = parens.pop().unwrap_or(pf),
                    _ => {}
                }
            }
            Tok::Pattern => end_command(&mut cur, &mut consumer, &mut pf, &mut loops, out),
        }
    }
    end_command(&mut cur, &mut consumer, &mut pf, &mut loops, out);
}

fn end_command(
    cur: &mut Vec<Word>,
    consumer: &mut bool,
    pf: &mut bool,
    loops: &mut [Loop],
    out: &mut Vec<Finding>,
) {
    if cur.is_empty() {
        return;
    }
    let words: Vec<&str> = cur.iter().map(|w| w.text.as_str()).collect();
    let line = cur[0].line;
    if *consumer {
        *consumer = false;
        if *pf && let Some(reader) = early_exit_reader(&words) {
            out.push(Finding { line, reader });
        }
    }
    let name = strip_wrappers(&words).first().copied().unwrap_or("");
    match name {
        "break" => {
            if let Some(l) = loops.last_mut() {
                l.early = true;
            }
        }
        "exit" | "return" => loops.iter_mut().for_each(|l| l.early = true),
        "set" => apply_set(&words[1..], pf),
        "shopt" => apply_shopt(&words[1..], pf),
        "bash" | "sh" | "dash" | "ksh" => nested_shell(cur, out),
        _ => {}
    }
    cur.clear();
}

/// `set -o pipefail`, `set +o pipefail`, and clusters such as `-euo pipefail`.
fn apply_set(args: &[&str], pf: &mut bool) {
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        i += 1;
        let on = match a.chars().next() {
            Some('-') => true,
            Some('+') => false,
            _ => break,
        };
        if a == "--" || a == "-" {
            break;
        }
        for c in a.chars().skip(1) {
            if c == 'o' {
                if args.get(i) == Some(&"pipefail") {
                    *pf = on;
                }
                i += 1;
            }
        }
    }
}

/// `shopt -so pipefail` and `shopt -u -o pipefail`.
fn apply_shopt(args: &[&str], pf: &mut bool) {
    let flags: String = args
        .iter()
        .filter(|a| a.starts_with('-'))
        .flat_map(|a| a.chars().skip(1))
        .collect();
    if flags.contains('o') && args.contains(&"pipefail") {
        if flags.contains('s') {
            *pf = true;
        } else if flags.contains('u') {
            *pf = false;
        }
    }
}

/// `bash -c '…'`: a script of its own, starting with the options given here
/// (a new shell does not inherit pipefail).
fn nested_shell(cur: &[Word], out: &mut Vec<Finding>) {
    let mut pf = false;
    let mut has_c = false;
    let mut i = 1;
    while i < cur.len() {
        let a = cur[i].text.as_str();
        i += 1;
        if a.starts_with("--") {
            continue;
        }
        if let Some(cluster) = a.strip_prefix('-').or_else(|| a.strip_prefix('+')) {
            for c in cluster.chars() {
                match c {
                    'c' => has_c = true,
                    'o' => {
                        if cur.get(i).is_some_and(|w| w.text == "pipefail") {
                            pf = a.starts_with('-');
                        }
                        i += 1;
                    }
                    _ => {}
                }
            }
            continue;
        }
        if has_c {
            let w = &cur[i - 1];
            if w.literal {
                scan_at(&w.text, w.line, pf, out);
            }
        }
        return;
    }
}

// ---------------------------------------------------------------------------
// Files.
// ---------------------------------------------------------------------------

/// Whether a tracked file is shell the gate reads: a `.sh`/`.bash` file, a
/// `.sh.shim`, a git hook, or an extensionless file with a shell shebang.
pub fn is_shell_path(path: &str, first_line: &str) -> bool {
    if path.ends_with(".sh")
        || path.ends_with(".bash")
        || path.ends_with(".sh.shim")
        || path.starts_with(".githooks/")
    {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.contains('.') {
        return false;
    }
    let Some(shebang) = first_line.strip_prefix("#!") else {
        return false;
    };
    let mut parts = shebang.split_whitespace();
    let mut interp = parts.next().unwrap_or("").rsplit('/').next().unwrap_or("");
    if interp == "env" {
        interp = parts.find(|p| !p.starts_with('-')).unwrap_or("");
    }
    matches!(interp, "sh" | "bash" | "dash" | "ksh")
}

/// Whether a tracked file is a workflow or a composite action.
pub fn is_workflow_path(path: &str) -> bool {
    let yaml = path.ends_with(".yml") || path.ends_with(".yaml");
    yaml && (path.starts_with(".github/workflows/")
        || (path.starts_with(".github/actions/")
            && (path.ends_with("/action.yml") || path.ends_with("/action.yaml"))))
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start_matches(' ').len()
}

/// Findings in a workflow or composite action's `run:` steps.
pub fn scan_workflow(text: &str) -> Result<Vec<Finding>, String> {
    let lines: Vec<&str> = text.lines().collect();
    for (n, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        if t.starts_with("defaults:") {
            return Err(format!(
                "line {}: `defaults:` can set every step's shell, and this scanner does not read it",
                n + 1
            ));
        }
        if t.starts_with("runs-on:") && t.contains("windows") {
            return Err(format!(
                "line {}: a Windows runner's default shell is pwsh, which this scanner does not read",
                n + 1
            ));
        }
    }
    let mut out = Vec::new();
    for (n, l) in lines.iter().enumerate() {
        let ind = indent(l);
        let t = &l[ind..];
        let (key_col, rest) = match t.strip_prefix("- ") {
            Some(r) => (ind + 2 + (r.len() - r.trim_start().len()), r.trim_start()),
            None => (ind, t),
        };
        let Some(value) = rest.strip_prefix("run:") else {
            continue;
        };
        let value = value.trim();
        let pf = match step_shell(&lines, n, key_col)? {
            None => false,
            Some(s) => match s.split_whitespace().next().unwrap_or("") {
                "bash" if !s.contains("{0}") => true,
                "sh" if !s.contains("{0}") => false,
                "bash" | "sh" => s.contains("pipefail"),
                _ => continue, // pwsh, python, cmd: not shell
            },
        };
        // Body lines and the 1-based file line of the first.
        let (body, first) = if value.starts_with('|') || value.starts_with('>') {
            let folded = value.starts_with('>');
            let mut end = n + 1;
            while end < lines.len()
                && (lines[end].trim().is_empty() || indent(lines[end]) > key_col)
            {
                end += 1;
            }
            while end > n + 1 && lines[end - 1].trim().is_empty() {
                end -= 1;
            }
            let block = &lines[n + 1..end];
            let strip = block
                .iter()
                .filter(|l| !l.trim().is_empty())
                .map(|l| indent(l))
                .min()
                .unwrap_or(0);
            let body: Vec<String> = block
                .iter()
                .map(|l| l.get(strip..).unwrap_or("").to_owned())
                .collect();
            let body = if folded {
                fold(&body)
            } else {
                body.join("\n") + "\n"
            };
            (body, n + 2)
        } else {
            let mut v = value.to_owned();
            if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
                v = v[1..v.len() - 1].replace("''", "'");
            } else if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                v = v[1..v.len() - 1]
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\");
            }
            (v + "\n", n + 1)
        };
        for f in scan_shell(&body, pf) {
            out.push(Finding {
                line: f.line + first - 1,
                reader: f.reader,
            });
        }
    }
    Ok(out)
}

/// A folded (`>`) block as the shell receives it, keeping one line per source
/// line so positions stay exact: a line break folds to a space, so each
/// folded line is joined to the next with a `\` continuation.
fn fold(body: &[String]) -> String {
    let mut s = String::new();
    for (k, l) in body.iter().enumerate() {
        s.push_str(l);
        let next_plain = body
            .get(k + 1)
            .is_some_and(|n| !n.trim().is_empty() && !n.starts_with(' '));
        if !l.trim().is_empty() && !l.starts_with(' ') && next_plain {
            s.push_str(" \\");
        }
        s.push('\n');
    }
    s
}

/// The `shell:` of the step whose `run:` key is on line `n` at column
/// `key_col`.
fn step_shell<'a>(lines: &[&'a str], n: usize, key_col: usize) -> Result<Option<&'a str>, String> {
    // The step starts at the `- ` item whose keys sit at `key_col`.
    let mut start = n;
    loop {
        let l = lines[start];
        let ind = indent(l);
        if !l.trim().is_empty() && ind + 2 <= key_col && l[ind..].starts_with("- ") {
            break;
        }
        if !l.trim().is_empty() && ind < key_col && start != n {
            return Err(format!("line {}: `run:` is not inside a step", n + 1));
        }
        if start == 0 {
            return Err(format!("line {}: `run:` is not inside a step", n + 1));
        }
        start -= 1;
    }
    let dash = indent(lines[start]);
    let mut k = start;
    while k < lines.len() {
        let l = lines[k];
        let ind = indent(l);
        if k > start && !l.trim().is_empty() && ind <= dash {
            break;
        }
        let key = if k == start {
            l[ind + 2..].trim_start()
        } else if ind == key_col {
            &l[ind..]
        } else {
            ""
        };
        if let Some(v) = key.strip_prefix("shell:") {
            return Ok(Some(v.trim()));
        }
        k += 1;
    }
    Ok(None)
}
