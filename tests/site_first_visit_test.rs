// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What a first-time visitor is told, checked against what happens.
//!
//! The 2026-11-10 audit followed the home page as a new reader would: read
//! the tiles, run the installer, run the quick start. Four statements did not
//! hold, and no test read any of them:
//!
//! - The quick start's "print a report" step printed every SIP message of the
//!   sample, 88 lines, with the report at the end.
//! - The installer told a Debian or Ubuntu reader to `apt install libpcap`.
//!   No such package exists there; `docs/install.md` names the right one.
//! - The home page had one tile for Asterisk and FreeSWITCH, titled "PBX".
//!   The README split the same guides under "PBX" and "Softswitch".
//! - `docs/troubleshooting.md` told readers of two defects to upgrade to "a
//!   later release", written before that release had a number.

// The quick start is run with the `sipnab` binary, and its flags are checked
// against the command line: both need the `native` feature.
#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

const README: &str = include_str!("../README.md");
const HOMEPAGE: &str = include_str!("../website/templates/index.html");
const INSTALLER: &str = include_str!("../website/static/install.sh");
const INSTALL_DOC: &str = include_str!("../docs/install.md");

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The text of the home page section with this `id`, from its opening tag to
/// the next `<section`.
fn section<'a>(html: &'a str, id: &str) -> Result<&'a str, TestError> {
    let at = html
        .find(&format!("id=\"{id}\""))
        .ok_or_else(|| format!("no section with id {id}"))?;
    let end = html[at..].find("<section").map_or(html.len(), |e| at + e);
    Ok(&html[at..end])
}

/// Minimal HTML unescape for the entities a shell command on the page uses.
fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// The commands of the quick start, in page order: the text of each
/// `<pre><code class="language-bash">` block.
fn quick_start_commands(html: &str) -> Result<Vec<String>, TestError> {
    const OPEN: &str = "<pre><code class=\"language-bash\">";
    let block = section(html, "quickstart")?;
    let mut out = Vec::new();
    let mut rest = block;
    while let Some(at) = rest.find(OPEN) {
        let from = at + OPEN.len();
        let len = rest[from..]
            .find("</code>")
            .ok_or("a quick start code block never closes")?;
        out.push(unescape(rest[from..from + len].trim()));
        rest = &rest[from + len..];
    }
    Ok(out)
}

/// Run one quick start command that needs no terminal and no network: a
/// `sipnab -N ...` line, in the directory that holds the sample capture.
fn run_headless(command: &str) -> Result<std::process::Output, TestError> {
    let args: Vec<&str> = command.split_whitespace().collect();
    if args.first() != Some(&"sipnab") || !args.contains(&"-N") {
        return Err(format!("not a headless sipnab command: {command}").into());
    }
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args[1..])
        .current_dir(repo().join("website/static/demos"))
        .env("NO_COLOR", "1")
        .output()?)
}

// ------------------------------------------------------------ quick start

#[test]
fn the_quick_start_has_an_install_a_download_and_a_first_result() -> Result<(), TestError> {
    let commands = quick_start_commands(HOMEPAGE)?;
    assert!(
        commands.len() >= 4,
        "the quick start shows {} command(s): {commands:?}",
        commands.len()
    );
    assert_eq!(
        commands[0], "curl -fsSL https://sipnab.com/install.sh | sh",
        "the first command installs sipnab with the published installer"
    );
    assert!(
        commands
            .iter()
            .any(|c| c == "curl -fsSLO https://sipnab.com/demos/sample-call.pcap"),
        "no step downloads the sample capture: {commands:?}"
    );
    assert!(
        repo()
            .join("website/static/demos/sample-call.pcap")
            .is_file(),
        "the quick start downloads /demos/sample-call.pcap, and the site no \
         longer ships that file"
    );
    Ok(())
}

#[test]
fn every_headless_quick_start_command_runs_on_the_sample() -> Result<(), TestError> {
    let commands = quick_start_commands(HOMEPAGE)?;
    let headless: Vec<&String> = commands
        .iter()
        .filter(|c| c.starts_with("sipnab ") && c.contains(" -N "))
        .collect();
    assert!(
        !headless.is_empty(),
        "the quick start has no command that prints a result without the \
         terminal UI: {commands:?}"
    );
    for command in headless {
        let out = run_headless(command)?;
        assert!(
            out.status.success(),
            "`{command}` exited {:?} in website/static/demos:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

#[test]
fn the_quick_start_report_step_prints_the_report_and_not_every_message() -> Result<(), TestError> {
    let commands = quick_start_commands(HOMEPAGE)?;
    let report = commands
        .iter()
        .find(|c| c.contains("--report"))
        .ok_or("the quick start has no --report step")?;
    let out = run_headless(report)?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.lines().any(|l| l.starts_with("Call-ID")),
        "`{report}` printed no report table:\n{stdout}"
    );
    assert!(
        stdout.contains("call-2c9d47@192.0.2.10") && stdout.contains("RTP Streams:"),
        "`{report}` does not show the sample's call and its media:\n{stdout}"
    );
    let message_lines = stdout
        .lines()
        .filter(|l| l.starts_with("INVITE sip:") || l.starts_with("Via: SIP/2.0"))
        .count();
    assert_eq!(
        message_lines, 0,
        "the step is titled as printing a report, and `{report}` also printed \
         the SIP messages themselves ({message_lines} request and Via lines). \
         `--no-cli-print` leaves the report alone"
    );
    assert!(
        stdout.lines().count() < 30,
        "`{report}` printed {} lines; the report of the sample is 15",
        stdout.lines().count()
    );
    Ok(())
}

#[test]
fn every_quick_start_flag_is_one_the_cli_defines() -> Result<(), TestError> {
    use clap::CommandFactory;
    let cmd = sipnab::cli::Cli::command();
    let longs: BTreeSet<String> = cmd
        .get_arguments()
        .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
        .collect();
    let shorts: BTreeSet<String> = cmd
        .get_arguments()
        .filter_map(|a| a.get_short().map(|c| format!("-{c}")))
        .collect();
    for command in quick_start_commands(HOMEPAGE)? {
        let Some(rest) = command
            .strip_prefix("sudo sipnab ")
            .or_else(|| command.strip_prefix("sipnab "))
        else {
            continue;
        };
        for word in rest.split_whitespace().filter(|w| w.starts_with('-')) {
            assert!(
                longs.contains(word) || shorts.contains(word),
                "the quick start command `{command}` uses `{word}`, which \
                 the command line does not define"
            );
        }
    }
    Ok(())
}

#[test]
fn the_quick_start_reader_returns_each_block_unescaped_and_in_order() -> Result<(), TestError> {
    let html = "<section id=\"quickstart\">\
        <pre><code class=\"language-bash\">a &amp;&amp; b</code></pre>\
        <pre><code class=\"language-text\">skipped</code></pre>\
        <pre><code class=\"language-bash\"> c &gt; d </code></pre>\
        </section><section id=\"demos\">\
        <pre><code class=\"language-bash\">not mine</code></pre></section>";
    assert_eq!(
        quick_start_commands(html)?,
        ["a && b", "c > d"],
        "the bash blocks of the quick start alone, unescaped and trimmed"
    );
    assert!(
        quick_start_commands("<section id=\"other\"></section>").is_err(),
        "a page with no quick start is an error, not an empty list"
    );
    assert!(
        quick_start_commands("<section id=\"quickstart\"><pre><code class=\"language-bash\">x")
            .is_err(),
        "a block that never closes is an error, not an empty list"
    );
    Ok(())
}

#[test]
fn only_a_headless_sipnab_command_is_run() {
    assert!(
        run_headless("curl -fsSL https://example.com/x | sh").is_err(),
        "a test must not run the installer"
    );
    assert!(
        run_headless("sipnab -I sample-call.pcap").is_err(),
        "without -N the command opens the terminal UI, which a test has no \
         terminal for"
    );
    assert!(
        run_headless("sudo sipnab -N -d eth0").is_err(),
        "a test must not run sudo or capture from an interface"
    );
}

// --------------------------------------------------------------- installer

/// The package that supplies libpcap at run time for each package manager,
/// as `docs/install.md` names them in its "The installer does not install
/// libpcap" passage: `(apt package, dnf package)`.
fn documented_libpcap_packages(doc: &str) -> Result<(String, String), TestError> {
    let line = doc
        .lines()
        .find(|l| l.starts_with("Install `") && l.contains("(Debian, Ubuntu)"))
        .ok_or("docs/install.md no longer says which libpcap package to install")?;
    let names: Vec<&str> = line.split('`').skip(1).step_by(2).collect();
    match names.as_slice() {
        [deb, rpm] => Ok(((*deb).to_string(), (*rpm).to_string())),
        other => Err(format!("expected two package names in `{line}`, found {other:?}").into()),
    }
}

/// The line the installer prints when it chose the build that needs libpcap.
fn installer_libpcap_hint(sh: &str) -> Result<&str, TestError> {
    sh.lines()
        .find(|l| l.contains("needs libpcap"))
        .ok_or_else(|| "install.sh no longer says the gnu build needs libpcap".into())
}

#[test]
fn the_installer_names_the_libpcap_package_the_install_page_names() -> Result<(), TestError> {
    let (deb, rpm) = documented_libpcap_packages(INSTALL_DOC)?;
    let hint = installer_libpcap_hint(INSTALLER)?;
    assert!(
        hint.contains(&format!("apt install {deb}")),
        "docs/install.md says the Debian and Ubuntu package is `{deb}`; the \
         installer prints: {hint}"
    );
    assert!(
        hint.contains(&format!("dnf install {rpm}")),
        "docs/install.md says the Fedora and RHEL package is `{rpm}`; the \
         installer prints: {hint}"
    );
    Ok(())
}

#[test]
fn the_installer_does_not_name_one_package_for_both_package_managers() -> Result<(), TestError> {
    let hint = installer_libpcap_hint(INSTALLER)?;
    assert!(
        !hint.contains("apt/dnf install"),
        "apt and dnf name the libpcap runtime package differently \
         (`apt install libpcap` answers \"Unable to locate package \
         libpcap\"): {hint}"
    );
    Ok(())
}

#[test]
fn the_package_reader_takes_both_names_from_the_install_page() -> Result<(), TestError> {
    assert_eq!(
        documented_libpcap_packages(
            "x\nInstall `libpcap0.8` (Debian, Ubuntu) or `libpcap` (Fedora, RHEL) and run it\n"
        )?,
        ("libpcap0.8".to_string(), "libpcap".to_string()),
        "the Debian name first, then the Fedora name"
    );
    assert!(
        documented_libpcap_packages("Install it.\n").is_err(),
        "a page that names no package is an error"
    );
    assert!(
        documented_libpcap_packages("Install `one` (Debian, Ubuntu) only\n").is_err(),
        "one name is not a pair"
    );
    assert!(
        installer_libpcap_hint("echo hello\n").is_err(),
        "an installer that prints no libpcap line is an error"
    );
    Ok(())
}

// ------------------------------------------------------------------- tiles

/// The titles of the home page's voice-stack tiles.
fn tile_titles(html: &str) -> Result<BTreeSet<String>, TestError> {
    let block = section(html, "voice-stack")?;
    Ok(block
        .split("<h3>")
        .skip(1)
        .filter_map(|s| s.split("</h3>").next())
        .map(str::to_string)
        .collect())
}

/// The role names the README's voice-stack section leads its bullets with:
/// `- **Name.**`.
fn readme_roles(readme: &str) -> Result<BTreeSet<String>, TestError> {
    let at = readme
        .find("## Add it to your voice stack")
        .ok_or("the README has no voice-stack section")?;
    let end = readme[at + 3..]
        .find("\n## ")
        .map_or(readme.len(), |e| at + 3 + e);
    Ok(readme[at..end]
        .lines()
        .filter_map(|l| l.strip_prefix("- **"))
        .filter_map(|l| l.split(".**").next())
        .map(str::to_string)
        .collect())
}

#[test]
fn the_readme_and_the_home_page_name_the_same_voice_stack_roles() -> Result<(), TestError> {
    let tiles = tile_titles(HOMEPAGE)?;
    let roles = readme_roles(README)?;
    assert!(tiles.len() >= 7, "read {} tiles: {tiles:?}", tiles.len());
    assert_eq!(
        tiles, roles,
        "the home page's voice-stack tiles and the README's voice-stack \
         bullets name different roles"
    );
    Ok(())
}

#[test]
fn asterisk_and_freeswitch_sit_under_telephony_platform() -> Result<(), TestError> {
    let tiles = tile_titles(HOMEPAGE)?;
    assert!(
        tiles.contains("Telephony platform"),
        "the owner chose \"Telephony platform\" for the Asterisk and \
         FreeSWITCH tile, because both do more than a PBX does: {tiles:?}"
    );
    assert!(!tiles.contains("PBX"), "a tile is still titled PBX");
    let block = section(HOMEPAGE, "voice-stack")?;
    let tile = block
        .split("<h3>")
        .find(|s| s.starts_with("Telephony platform"))
        .ok_or("no Telephony platform tile")?;
    for guide in [
        "@/docs/asterisk.md",
        "@/docs/asterisk-sipnab.md",
        "@/docs/freeswitch.md",
        "@/docs/freeswitch-sipnab.md",
    ] {
        assert!(tile.contains(guide), "the tile does not link {guide}");
    }
    Ok(())
}

#[test]
fn the_tile_and_role_readers_read_their_sections_only() -> Result<(), TestError> {
    let html = "<section id=\"features\"><h3>Inspect</h3></section>\
        <section class=\"x\" id=\"voice-stack\"><h3>SIP proxy</h3><h3>Metrics</h3></section>\
        <section><h3>After</h3></section>";
    let expected: BTreeSet<String> = ["SIP proxy", "Metrics"].map(String::from).into();
    assert_eq!(
        tile_titles(html)?,
        expected,
        "the headings of the voice-stack section, and of no other"
    );
    assert!(
        tile_titles("<section id=\"features\"></section>").is_err(),
        "a page with no voice-stack section is an error"
    );

    let readme = "## Before\n- **Not a role.** x\n## Add it to your voice stack\n\
        - **SIP proxy.** a\n  - [nested](x)\n  - **Nested, not a role.** n\n- **Metrics.** b\n- plain\n## After\n- **Later.** c\n";
    assert_eq!(
        readme_roles(readme)?,
        expected,
        "the top-level bold bullets of the voice-stack section, and of no other"
    );
    assert!(
        readme_roles("## Something else\n").is_err(),
        "a README with no voice-stack section is an error"
    );
    Ok(())
}

// --------------------------------------------------------- later release

/// Whether a line tells the reader to upgrade to a release it does not name.
///
/// "Upgrade" and "a later release" on one line is the instruction; "the same
/// later release" continues one. A line that only says a later release will
/// change something, such as a deprecation notice, gives no instruction and
/// is not reported.
fn names_no_release(line: &str) -> bool {
    let line = line.to_lowercase();
    line.contains("the same later release")
        || (line.contains("upgrade")
            && ["a later release", "a future release"]
                .iter()
                .any(|p| line.contains(p)))
}

/// Every Markdown file under `dir`, recursively.
fn markdown_under(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            markdown_under(&path, out);
        } else if path.extension().is_some_and(|x| x == "md") {
            out.push(path);
        }
    }
}

#[test]
fn no_user_page_sends_the_reader_to_an_unnamed_later_release() -> Result<(), TestError> {
    let mut files = Vec::new();
    markdown_under(&repo().join("docs"), &mut files);
    files.push(repo().join("README.md"));
    files.sort();
    let mut scanned = 0usize;
    let mut problems = Vec::new();
    for path in files {
        let shown = path
            .strip_prefix(repo())
            .unwrap_or(&path)
            .display()
            .to_string();
        // Design records and research notes describe plans; a user page
        // describes what a release does.
        if shown.starts_with("docs/design/")
            || shown.starts_with("docs/research/")
            || shown.ends_with(".local.md")
        {
            continue;
        }
        scanned += 1;
        let text = std::fs::read_to_string(&path)?;
        for (n, line) in text.lines().enumerate() {
            if names_no_release(line) {
                problems.push(format!("{shown}:{}: {}", n + 1, line.trim()));
            }
        }
    }
    assert!(scanned > 100, "read {scanned} pages; the walk is broken");
    assert!(
        problems.is_empty(),
        "these lines tell the reader to upgrade to a release without naming \
         it. CHANGELOG.md says which release carries the fix; name it:\n{}",
        problems.join("\n")
    );
    Ok(())
}

#[test]
fn the_unnamed_release_reader_reports_an_upgrade_to_no_named_release() {
    assert!(
        names_no_release("- **Fix:** upgrade. A later release stops on its own"),
        "the line docs/troubleshooting.md had"
    );
    assert!(
        names_no_release("The same later release makes a terminal interface"),
        "a sentence that continues such an instruction"
    );
    assert!(
        names_no_release("UPGRADE: A FUTURE RELEASE has the fix"),
        "case does not matter"
    );
}

#[test]
fn the_unnamed_release_reader_leaves_named_releases_and_notices_alone() {
    assert!(
        !names_no_release("- **Fix:** upgrade to 0.5.235 or later."),
        "an instruction that names the release"
    );
    assert!(
        !names_no_release("Later releases fix three `netmap:` failures."),
        "a sentence that introduces a table of fixed releases"
    );
    assert!(
        !names_no_release("counts may change in later releases"),
        "a caution about the future is not an instruction"
    );
    assert!(
        !names_no_release("The flag is still accepted. A later release removes it."),
        "a deprecation notice is not an instruction to upgrade"
    );
    assert!(
        !names_no_release("A flag that a release removed and a later release restored"),
        "a rule about release history"
    );
    assert!(
        !names_no_release("| Move to a newer release | [Upgrade sipnab](#upgrade-sipnab) |"),
        "a link to the upgrade steps names no fix and promises none"
    );
    assert!(
        !names_no_release("upgrade"),
        "the word alone points at no release"
    );
    assert!(!names_no_release(""), "an empty line");
}
