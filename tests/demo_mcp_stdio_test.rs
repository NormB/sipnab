// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `demos/mcp-stdio.sh` runs on the bash macOS ships, 3.2
//! (DEMO-MCP-STDIO-BASH32).
//!
//! The script is what `docs/examples.md` tells a reader to run for one MCP
//! tool call over stdio. It talked to the server through `coproc`, which bash
//! gained in 4.0, and expanded empty arrays under `set -u`, which bash before
//! 4.4 refuses as an unbound variable. On macOS, whose `/bin/bash` is 3.2, it
//! ended at the first of the two. No test ran it.
//!
//! Two kinds of test hold it now:
//!
//! - **It runs.** Each test starts the script with `/bin/bash` against the
//!   real binary, or against a stand-in server for the cases a real server
//!   does not produce (one that never answers, one that never finishes
//!   loading). On the macOS leg of CI `/bin/bash` is 3.2, so that leg runs
//!   every one of these on the old shell.
//! - **It uses nothing bash 3.2 lacks.** A reading of the script's code
//!   lines, which fails on Linux too, where `/bin/bash` is newer and would
//!   run a `coproc` without complaint.
//!
//! Every child is started in its own process group, tied to the test thread,
//! and the whole group is stopped when a run outlasts its deadline, so a
//! script that hangs fails its test and leaves neither itself nor a server
//! behind.
#![cfg(all(unix, feature = "mcp"))]

#[path = "support/executable.rs"]
mod executable;

include!("support/timeout.rs");

use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

type TestError = Box<dyn std::error::Error>;

/// The script under test, from the crate root.
const SCRIPT: &str = "demos/mcp-stdio.sh";

/// A capture with one call, `test-call-1@192.0.2.1`.
const CAPTURE: &str = "tests/fixtures/sip_call.pcap";

/// The shell the tests run the script with: the system's, which is what
/// `#!/usr/bin/env bash` finds on a macOS without a newer bash installed.
const BASH: &str = "/bin/bash";

/// What one run of the script left behind.
struct Finished {
    /// Everything on stdout.
    stdout: String,
    /// Everything on stderr.
    stderr: String,
    /// The exit code, or `None` when a signal ended the run.
    code: Option<i32>,
    /// How long the run took.
    took: Duration,
}

/// One run of the script: its arguments and environment.
struct Run<'a> {
    /// Arguments after the script's name.
    args: &'a [&'a str],
    /// Variables set for the run.
    env: Vec<(&'a str, String)>,
    /// The binary `SIPNAB_BIN` names; the real one unless a test replaces it.
    bin: String,
    /// Where the run keeps its temporary files.
    tmp: tempfile::TempDir,
}

impl<'a> Run<'a> {
    /// A run of the script with `args` against the real binary.
    fn new(args: &'a [&'a str]) -> Result<Self, TestError> {
        Ok(Self {
            args,
            env: Vec::new(),
            bin: env!("CARGO_BIN_EXE_sipnab").to_string(),
            tmp: tempfile::tempdir()?,
        })
    }

    /// Set `name` to `value` for the run.
    fn env(mut self, name: &'a str, value: &str) -> Self {
        self.env.push((name, value.to_string()));
        self
    }

    /// Drive `bin` in place of the real binary.
    fn bin(mut self, bin: &Path) -> Self {
        self.bin = bin.display().to_string();
        self
    }

    /// Run the script and wait for it, for at most `wait`.
    ///
    /// # Errors
    /// When the script cannot be started, or is still running after `wait`;
    /// its process group is stopped first.
    fn finish(&self, wait: Duration) -> Result<Finished, TestError> {
        let mut cmd = Command::new(BASH);
        cmd.arg(SCRIPT)
            .args(self.args)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("SIPNAB_BIN", &self.bin)
            .env("TMPDIR", self.tmp.path())
            .env("HOME", self.tmp.path())
            .env("SIPNAB_CONFIG", self.tmp.path().join("no-such-config.toml"))
            .env_remove("MCP_FILE_ROOT")
            .env_remove("MCP_NODE_NAME")
            .env_remove("MCP_TIMEOUT")
            .env_remove("MCP_MAX_POLLS")
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let started = Instant::now();
        let mut child = cmd.tied_to_test().spawn()?;
        let mut out = child.stdout.take().ok_or("piped stdout")?;
        let mut err = child.stderr.take().ok_or("piped stderr")?;
        let stdout = thread::spawn(move || {
            let mut text = String::new();
            let _ = out.read_to_string(&mut text);
            text
        });
        let stderr = thread::spawn(move || {
            let mut text = String::new();
            let _ = err.read_to_string(&mut text);
            text
        });
        let deadline = started + wait;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            thread::sleep(Duration::from_millis(20));
        };
        let took = started.elapsed();
        // The script's own children are in its group. Stop whatever is left
        // of it, whether the script ended or not: after a clean run this
        // finds nothing, and `nothing_is_left_running` checks that first.
        let group = libc::pid_t::try_from(child.id())?;
        let left = group_is_alive(group);
        // SAFETY: killpg(2) on the group this test created for a child it
        // has not reaped, or has just reaped while members remain; it
        // touches no memory.
        unsafe { libc::killpg(group, libc::SIGKILL) };
        let Some(status) = status else {
            let _ = child.wait();
            return Err(
                format!("{SCRIPT} {:?} was still running after {wait:?}", self.args).into(),
            );
        };
        let finished = Finished {
            stdout: stdout.join().map_err(|_| "the stdout reader panicked")?,
            stderr: stderr.join().map_err(|_| "the stderr reader panicked")?,
            code: status.code(),
            took,
        };
        if left {
            return Err(format!(
                "{SCRIPT} {:?} exited and left a process of its group running; stderr: {}",
                self.args, finished.stderr
            )
            .into());
        }
        Ok(finished)
    }

    /// Entries left in the run's temporary directory.
    fn leftovers(&self) -> Result<Vec<PathBuf>, TestError> {
        Ok(std::fs::read_dir(self.tmp.path())?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect())
    }
}

/// Whether any process of `group` other than a reaped leader is alive.
fn group_is_alive(group: libc::pid_t) -> bool {
    // The script has just exited; a server it stopped may take a moment to
    // be gone. Signal 0 asks without signaling.
    let deadline = Instant::now() + test_timeout(5);
    loop {
        // SAFETY: killpg(2) with signal 0 only checks for members; it
        // touches no memory.
        let alive = unsafe { libc::killpg(group, 0) } == 0;
        if !alive || Instant::now() >= deadline {
            return alive;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// How long a run that should work may take.
fn run_wait() -> Duration {
    test_timeout(120)
}

/// An executable file `name` in `dir` holding `body`, written by
/// `support/executable.rs` so that this process never holds it open for
/// writing (a sibling test's child could inherit that, and the exec would
/// fail with "Text file busy").
fn executable(dir: &Path, name: &str, body: &str) -> Result<PathBuf, TestError> {
    let path = dir.join(name);
    executable::write_executable(&path, body)?;
    Ok(path)
}

/// A stand-in MCP server in POSIX sh. It answers `initialize`, answers
/// `capture_status` with `source_exhausted` set to `$FAKE_EXHAUSTED`
/// (default `true`), and answers any other tool with `$FAKE_ANSWER` as the
/// text. With `FAKE_SILENT=1` it reads and answers nothing. With
/// `FAKE_NOISE=1` it writes a notification and a reply to another request
/// before each answer.
const FAKE_SERVER: &str = r#"#!/bin/sh
while IFS= read -r line; do
  [ "${FAKE_SILENT:-0}" = 1 ] && continue
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  [ -n "$id" ] || continue
  if [ "${FAKE_NOISE:-0}" = 1 ]; then
    printf '{"jsonrpc":"2.0","method":"notifications/message","params":{}}\n'
    printf '{"jsonrpc":"2.0","id":9999,"result":{"content":[{"type":"text","text":"not yours"}]}}\n'
  fi
  case "$line" in
    *'"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id" ;;
    *'"capture_status"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"{\\"source_exhausted\\":%s}"}]}}\n' "$id" "${FAKE_EXHAUSTED:-true}" ;;
    *)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"%s"}]}}\n' "$id" "${FAKE_ANSWER:-plain words}" ;;
  esac
done
"#;

/// `text` parsed as JSON, with the text in the error when it is not.
fn json(text: &str) -> Result<serde_json::Value, TestError> {
    serde_json::from_str(text).map_err(|e| format!("not JSON ({e}): {text}").into())
}

// ── It runs ──────────────────────────────────────────────────────────────

/// One tool call against a capture in the tree prints the tool's answer as
/// JSON: the call in the capture, with its final state, and nothing on
/// stderr.
#[test]
fn one_tool_call_prints_the_answer_as_json() -> Result<(), TestError> {
    let run = Run::new(&[CAPTURE, "list_dialogs"])?;
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    let answer = json(&done.stdout)?;
    assert!(
        done.stdout.contains("test-call-1@192.0.2.1"),
        "the capture's call is in the answer: {answer}"
    );
    assert_eq!(done.stderr, "", "a run that works says nothing on stderr");
    Ok(())
}

/// The third argument reaches the tool as its arguments.
#[test]
fn json_arguments_reach_the_tool() -> Result<(), TestError> {
    let run = Run::new(&[CAPTURE, "top_talkers", r#"{"by":"ip","limit":1}"#])?;
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    let answer = json(&done.stdout)?;
    let talkers = answer["talkers"].as_array().ok_or("no talkers array")?;
    assert_eq!(talkers.len(), 1, "limit 1 was applied: {answer}");
    Ok(())
}

/// The answer is what is read once the capture is loaded: the call has its
/// BYE, which a call asked about too early does not.
#[test]
fn the_answer_comes_after_the_capture_is_loaded() -> Result<(), TestError> {
    let run = Run::new(&[CAPTURE, "capture_status"])?;
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    let answer = json(&done.stdout)?;
    assert_eq!(
        answer["source_exhausted"],
        serde_json::Value::Bool(true),
        "the source was read to its end before the call: {answer}"
    );
    Ok(())
}

/// `MCP_NODE_NAME` is the name the server reports, so a recording does not
/// carry the name of the machine that made it.
#[test]
fn the_node_name_variable_names_the_server() -> Result<(), TestError> {
    let run = Run::new(&[CAPTURE, "capture_status"])?.env("MCP_NODE_NAME", "demo-node");
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    assert!(
        done.stdout.contains("demo-node"),
        "the node name is in the answer: {}",
        done.stdout
    );
    Ok(())
}

/// `MCP_FILE_ROOT` is passed on as `--mcp-file-root`: the stand-in server
/// records its arguments, and the flag and the directory are among them.
#[test]
fn the_file_root_variable_becomes_the_file_root_flag() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let seen = dir.path().join("argv");
    let recorder = executable(
        dir.path(),
        "recorder",
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nexec '{}'\n",
            seen.display(),
            executable(dir.path(), "fake", FAKE_SERVER)?.display()
        ),
    )?;
    let run = Run::new(&[CAPTURE, "anything"])?
        .bin(&recorder)
        .env("MCP_FILE_ROOT", "/srv/captures")
        .env("MCP_NODE_NAME", "demo-node");
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    let argv = std::fs::read_to_string(&seen)?;
    let argv: Vec<&str> = argv.lines().collect();
    assert_eq!(
        argv,
        [
            "--mcp",
            "-N",
            "-I",
            CAPTURE,
            "--mcp-file-root",
            "/srv/captures",
            "--node-name",
            "demo-node",
            "--quiet"
        ],
        "the server's whole command line"
    );
    Ok(())
}

/// With neither variable set the server gets no flag for them, and no empty
/// argument either: on bash 3.2 an empty array expanded under `set -u` ended
/// the script, and a careless fix passes `""`.
#[test]
fn unset_variables_add_no_argument() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let seen = dir.path().join("argv");
    let recorder = executable(
        dir.path(),
        "recorder",
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nexec '{}'\n",
            seen.display(),
            executable(dir.path(), "fake", FAKE_SERVER)?.display()
        ),
    )?;
    let run = Run::new(&[CAPTURE, "anything"])?.bin(&recorder);
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    let argv = std::fs::read_to_string(&seen)?;
    let argv: Vec<&str> = argv.lines().collect();
    assert_eq!(
        argv,
        ["--mcp", "-N", "-I", CAPTURE, "--quiet"],
        "the server's whole command line"
    );
    Ok(())
}

/// An answer that is not JSON is printed as it came, not replaced by the
/// formatter's parse error.
#[test]
fn an_answer_that_is_not_json_is_printed_as_it_came() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let fake = executable(dir.path(), "fake", FAKE_SERVER)?;
    let run = Run::new(&[CAPTURE, "anything"])?
        .bin(&fake)
        .env("FAKE_ANSWER", "missing field refs");
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    assert_eq!(done.stdout, "missing field refs\n", "the answer, unchanged");
    Ok(())
}

/// The server's stream carries more than answers to this script's last
/// request: notifications, and replies to other requests. Each is passed
/// over, and the answer printed is the one that quotes the request's id.
#[test]
fn lines_that_answer_something_else_are_passed_over() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let fake = executable(dir.path(), "fake", FAKE_SERVER)?;
    let run = Run::new(&[CAPTURE, "anything"])?
        .bin(&fake)
        .env("FAKE_NOISE", "1")
        .env("FAKE_ANSWER", "the real answer");
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    assert_eq!(
        done.stdout, "the real answer\n",
        "the reply to this request"
    );
    Ok(())
}

/// A tool the server does not have is reported in the server's words, and
/// the script still ends.
#[test]
fn an_unknown_tool_is_reported_in_the_servers_words() -> Result<(), TestError> {
    let run = Run::new(&[CAPTURE, "no_such_tool"])?;
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    assert!(
        done.stdout.contains("no_such_tool") || done.stdout.starts_with("error: "),
        "the server's refusal is printed: {}",
        done.stdout
    );
    Ok(())
}

// ── It ends, and says why, when it cannot work ───────────────────────────

/// No arguments: the usage line, and a failing exit code.
#[test]
fn no_arguments_prints_the_usage() -> Result<(), TestError> {
    let run = Run::new(&[])?;
    let done = run.finish(run_wait())?;
    assert_ne!(done.code, Some(0), "stdout: {}", done.stdout);
    assert!(
        done.stderr
            .contains("usage: mcp-stdio.sh <capture> <tool> [json-arguments]"),
        "{}",
        done.stderr
    );
    Ok(())
}

/// A capture with no tool: the usage line again.
#[test]
fn a_capture_without_a_tool_prints_the_usage() -> Result<(), TestError> {
    let run = Run::new(&[CAPTURE])?;
    let done = run.finish(run_wait())?;
    assert_ne!(done.code, Some(0), "stdout: {}", done.stdout);
    assert!(
        done.stderr
            .contains("usage: mcp-stdio.sh <capture> <tool> [json-arguments]"),
        "{}",
        done.stderr
    );
    Ok(())
}

/// A capture that is not there is named, and no server is started.
#[test]
fn a_missing_capture_is_named() -> Result<(), TestError> {
    let run = Run::new(&["tests/fixtures/no-such.pcap", "list_dialogs"])?;
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(1), "stdout: {}", done.stdout);
    assert_eq!(
        done.stderr, "no capture at tests/fixtures/no-such.pcap\n",
        "the one line that says what is missing"
    );
    Ok(())
}

/// A `SIPNAB_BIN` that names nothing is named at once, not reported 20
/// seconds later as a server that did not answer.
#[test]
fn a_binary_that_does_not_exist_is_named_at_once() -> Result<(), TestError> {
    let run = Run::new(&[CAPTURE, "list_dialogs"])?.bin(Path::new("/nonexistent/sipnab"));
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(1), "stdout: {}", done.stdout);
    assert!(
        done.stderr.contains("/nonexistent/sipnab") && done.stderr.contains("SIPNAB_BIN"),
        "the binary and the variable are named: {}",
        done.stderr
    );
    assert!(
        done.took < test_timeout(10),
        "it took {:?}, which is a wait for an answer",
        done.took
    );
    Ok(())
}

/// Without `jq` the script says so. Every reply is read with `jq`, so
/// without this check the run ended as "no initialize reply".
#[test]
fn a_missing_jq_is_named() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    // A PATH holding what the script uses, less jq.
    for tool in ["mktemp", "mkfifo", "rm", "cat", "sleep", "env", "dirname"] {
        let found = ["/bin", "/usr/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
            .ok_or_else(|| format!("no {tool} in /bin or /usr/bin"))?;
        std::os::unix::fs::symlink(found, dir.path().join(tool))?;
    }
    let run = Run::new(&[CAPTURE, "list_dialogs"])?.env("PATH", &dir.path().display().to_string());
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(1), "stdout: {}", done.stdout);
    assert!(done.stderr.contains("jq"), "jq is named: {}", done.stderr);
    Ok(())
}

/// A server that never answers ends the run after `MCP_TIMEOUT` seconds with
/// a message that names the binary, and the server is stopped.
#[test]
fn a_server_that_never_answers_ends_the_run() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let fake = executable(dir.path(), "fake", FAKE_SERVER)?;
    let run = Run::new(&[CAPTURE, "anything"])?
        .bin(&fake)
        .env("FAKE_SILENT", "1")
        .env("MCP_TIMEOUT", "1");
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(1), "stdout: {}", done.stdout);
    assert!(
        done.stderr.contains("no initialize reply from") && done.stderr.contains("fake"),
        "{}",
        done.stderr
    );
    assert_eq!(done.stdout, "", "nothing is printed for a call never made");
    assert!(
        done.took < test_timeout(10),
        "MCP_TIMEOUT=1 was not the wait: the run took {:?}",
        done.took
    );
    Ok(())
}

/// A capture that never finishes loading ends the run after `MCP_MAX_POLLS`
/// polls, naming the capture.
#[test]
fn a_capture_that_never_loads_ends_the_run() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let fake = executable(dir.path(), "fake", FAKE_SERVER)?;
    let run = Run::new(&[CAPTURE, "anything"])?
        .bin(&fake)
        .env("FAKE_EXHAUSTED", "false")
        .env("MCP_MAX_POLLS", "3");
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(1), "stdout: {}", done.stdout);
    assert_eq!(
        done.stderr,
        format!("mcp-stdio: {CAPTURE} never finished loading\n"),
        "the one line that says what did not happen"
    );
    assert!(
        done.took < test_timeout(10),
        "MCP_MAX_POLLS=3 was not the bound: the run took {:?}",
        done.took
    );
    Ok(())
}

/// A server that ends before it answers (here: one that exits at once) is
/// reported the same way and does not hang the run on a pipe nobody writes.
#[test]
fn a_server_that_exits_at_once_ends_the_run() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let quitter = executable(dir.path(), "quitter", "#!/bin/sh\nexit 3\n")?;
    let run = Run::new(&[CAPTURE, "anything"])?
        .bin(&quitter)
        .env("MCP_TIMEOUT", "60");
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(1), "stdout: {}", done.stdout);
    assert!(
        done.stderr.contains("no initialize reply from"),
        "{}",
        done.stderr
    );
    assert!(
        done.took < test_timeout(20),
        "a server that is gone was waited for: the run took {:?} of a 60 s timeout",
        done.took
    );
    Ok(())
}

// ── It cleans up ─────────────────────────────────────────────────────────

/// A run that works leaves nothing in its temporary directory. (`finish`
/// has already failed the run if a process of its group was left.)
#[test]
fn a_run_that_works_leaves_no_file_behind() -> Result<(), TestError> {
    let run = Run::new(&[CAPTURE, "list_dialogs"])?;
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(0), "stderr: {}", done.stderr);
    let left = run.leftovers()?;
    assert!(left.is_empty(), "left in TMPDIR: {left:?}");
    Ok(())
}

/// A run that fails after it started its server leaves nothing either.
#[test]
fn a_run_that_fails_leaves_no_file_behind() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let fake = executable(dir.path(), "fake", FAKE_SERVER)?;
    let run = Run::new(&[CAPTURE, "anything"])?
        .bin(&fake)
        .env("FAKE_SILENT", "1")
        .env("MCP_TIMEOUT", "1");
    let done = run.finish(run_wait())?;
    assert_eq!(done.code, Some(1), "stdout: {}", done.stdout);
    let left = run.leftovers()?;
    assert!(left.is_empty(), "left in TMPDIR: {left:?}");
    Ok(())
}

// ── It uses nothing bash 3.2 lacks ───────────────────────────────────────

/// The script's code: each line less its comment, blank lines dropped. A `#`
/// starts a comment at the start of a line or after a space; the script has
/// no `#` of that shape inside a string.
fn code_lines(script: &str) -> Vec<(usize, String)> {
    script
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let code = match line.find(" #") {
                _ if line.trim_start().starts_with('#') => "",
                Some(at) => &line[..at],
                None => line,
            };
            (!code.trim().is_empty()).then(|| (i + 1, code.to_string()))
        })
        .collect()
}

/// What bash 3.2 does not have, as (text to look for, what it is).
const NOT_IN_BASH_32: &[(&str, &str)] = &[
    ("coproc", "coprocesses are bash 4.0"),
    ("mapfile", "mapfile is bash 4.0"),
    ("readarray", "readarray is bash 4.0"),
    ("declare -A", "associative arrays are bash 4.0"),
    ("local -A", "associative arrays are bash 4.0"),
    ("|&", "the |& pipe is bash 4.0"),
    ("&>>", "the &>> redirection is bash 4.0"),
    (",,}", "case conversion in an expansion is bash 4.0"),
    ("^^}", "case conversion in an expansion is bash 4.0"),
    ("wait -n", "wait -n is bash 4.3"),
    ("declare -n", "name references are bash 4.3"),
    ("local -n", "name references are bash 4.3"),
    ("${!", "indirect and key expansions differ before bash 4"),
    ("[-1]", "negative array indexes are bash 4.3"),
    ("globstar", "globstar is bash 4.0"),
    ("lastpipe", "lastpipe is bash 4.2"),
    ("printf -v", "printf -v into an array element is bash 4.1"),
    ("BASHPID", "BASHPID is bash 4.0"),
    ("EPOCHSECONDS", "EPOCHSECONDS is bash 5.0"),
    (";;&", "the ;;& case terminator is bash 4.0"),
    (";&", "the ;& case terminator is bash 4.0"),
];

/// No code line of the script uses a construct bash 3.2 lacks.
#[test]
fn the_script_uses_no_construct_bash_32_lacks() -> Result<(), TestError> {
    let script = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT))?;
    let mut found = Vec::new();
    for (line, code) in code_lines(&script) {
        for (text, why) in NOT_IN_BASH_32 {
            if code.contains(text) {
                found.push(format!("line {line}: `{text}` ({why}): {}", code.trim()));
            }
        }
    }
    assert!(found.is_empty(), "{SCRIPT}:\n  {}", found.join("\n  "));
    Ok(())
}

/// Under `set -u`, bash before 4.4 refuses `"${array[@]}"` of an empty array
/// as an unbound variable. Every array expansion in the script is written
/// `${array[@]+"${array[@]}"}`, which expands to nothing when it is empty.
#[test]
fn every_array_expansion_survives_an_empty_array_under_set_u() -> Result<(), TestError> {
    let script = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT))?;
    let mut bare = Vec::new();
    let mut seen = 0;
    for (line, code) in code_lines(&script) {
        let mut rest = code.as_str();
        while let Some(at) = rest.find("[@]") {
            let before = &rest[..at];
            let name_at = before.rfind("${").ok_or("an [@] with no ${ before it")?;
            let name = &before[name_at + 2..];
            let after = &rest[at + 3..];
            seen += 1;
            // Guarded: `${name[@]+"${name[@]}"}`. The outer expansion is
            // followed by `+`, and the inner one sits right after `+"`.
            let outer = after.starts_with('+');
            let inner = before[..name_at].ends_with("+\"");
            if !outer && !inner {
                bare.push(format!(
                    "line {line}: ${{{name}[@]}} is not guarded: {}",
                    code.trim()
                ));
            }
            rest = after;
        }
    }
    assert!(
        seen > 0,
        "the script expands no array; this test checks nothing"
    );
    assert!(bare.is_empty(), "{SCRIPT}:\n  {}", bare.join("\n  "));
    Ok(())
}

/// The reading above finds what it looks for: a line with a coprocess and a
/// bare array expansion is reported, a comment that names them is not.
#[test]
fn the_reading_sees_code_and_not_comments() {
    let sample =
        "# coproc in a comment\ncoproc SRV { x \"${A[@]}\"; } # trailing\n\n  # indented\n";
    let lines = code_lines(sample);
    assert_eq!(lines.len(), 1, "one code line: {lines:?}");
    assert_eq!(lines[0].0, 2, "its line number");
    assert!(lines[0].1.contains("coproc"), "the code is kept: {lines:?}");
    assert!(
        !lines[0].1.contains("trailing"),
        "the comment is cut: {lines:?}"
    );
}

/// On macOS the system bash is 3.2, which is what makes the tests above a
/// check of the old shell there. If Apple ships another, this says so, and
/// the claim in the file's header needs another look.
#[cfg(target_os = "macos")]
#[test]
fn the_system_bash_on_macos_is_32() -> Result<(), TestError> {
    let out = Command::new(BASH).arg("--version").output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("version 3.2"),
        "{BASH} is no longer 3.2, so no CI leg runs the script on it: {text}"
    );
    Ok(())
}

/// The macOS leg of CI runs the whole suite, this file included: the step
/// is there, it runs every target, and it names no target to leave out. That
/// leg is the one place the script meets bash 3.2.
#[test]
fn the_macos_leg_of_ci_runs_the_whole_suite() -> Result<(), TestError> {
    let ci = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml"),
    )?;
    let at = ci
        .find("- name: Test (macOS, every target)")
        .ok_or("ci.yml has no macOS step that runs every target")?;
    let step: String = ci[at..].lines().take(3).collect::<Vec<_>>().join("\n");
    assert!(
        step.contains("if: runner.os == 'macOS'")
            && step.contains("run: python3 scripts/parallel-tests.py -- --all-features"),
        "the macOS step no longer runs the whole suite with every feature:\n{step}"
    );
    assert!(
        !step.contains("--skip") && !step.contains("-E "),
        "the macOS step leaves tests out:\n{step}"
    );
    Ok(())
}

include!("support/child_lifetime.rs");
