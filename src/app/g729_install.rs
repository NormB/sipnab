// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! `sipnab g729 install` and `sipnab g729 status`: the G.729 codebook tables
//! on this host.
//!
//! sipnab ships no ITU-T table values (docs/g729.md). `install` takes the
//! ITU-T G.729 software package from itu.int, or a copy the operator already
//! has, checks its pinned sha256, builds the table file in memory with
//! `g729::import_from_itu` (which checks the pinned sha256 of the VALUES),
//! writes it with mode 0644 by an atomic rename, and deletes the download.
//! The package goes from the ITU to the operator; sipnab never hosts or
//! mirrors it.
//!
//! `--from` takes the package zip, a directory extracted from it, or a table
//! file installed on another host, and never opens a connection. Every
//! refusal names the expected and the actual hash.
//!
//! The command line, REST, MCP and vCon export never download on their own;
//! only this command, and the terminal UI when the operator says yes or set
//! `[g729] auto_install = true`, reach the network for the tables.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use crate::cli::g729_args::{G729Cli, G729Command};
use crate::rtp::g729_tables::{TABLE_FILE_NAME, TableLocation, hex};

/// The ITU-T G.729 (06/2012) software package, Release 3: the public link,
/// which needs no login.
pub const PACKAGE_URL: &str =
    "https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-G.729-201206-I!!SOFT-ZST-E&type=items";

/// The package's pinned sha256.
pub const PACKAGE_SHA256: &str = "979680ff3b52b13a5701453178efd32b53e340114638fd330fdb6669eec86620";

/// The package's size in bytes, the most a download reads.
pub const PACKAGE_BYTES: usize = 18_476_968;

/// Why the command exists, in the words every G.729 page uses: the values
/// come from the user's own copy of the package. `crates/g729/PROVENANCE.md`
/// holds the verbatim notices, the holders and the package hash.
pub const WHY: &str = "The trained codebook values of G.729 are published in the reference C \
code of the ITU-T G.729 software package, and that code's notice keeps its authors' rights. So sipnab reads them from your own copy of the package instead of shipping them. \
Everything sipnab ships is MIT OR Apache-2.0. Details: \
https://github.com/NormB/sipnab/blob/main/crates/g729/PROVENANCE.md";

/// Where the command reads its answers and writes its output.
pub struct Io<'a> {
    /// The operator's answer to the question.
    pub input: &'a mut dyn BufRead,
    /// What the command reports.
    pub out: &'a mut dyn Write,
    /// Refusals.
    pub err: &'a mut dyn Write,
}

/// Fetches the package from `url`: an HTTPS GET in the binary, a stand-in in
/// tests.
pub type Fetch<'a> = &'a dyn Fn(&str) -> Result<Vec<u8>, String>;

/// Run `sipnab g729` from the process arguments after `sipnab`: parse, read
/// the config file for `[g729] tables`, and run against the terminal.
#[must_use]
pub fn main(args: impl IntoIterator<Item = std::ffi::OsString>) -> i32 {
    use clap::Parser;
    let cli = match G729Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => return crate::output::stdout::clap_exit_code(&e),
    };
    let work_root = std::env::temp_dir();
    if let G729Command::InternalFetch { as_user } = &cli.command {
        // The child of an install started as root: it reads no config file,
        // and its standard output carries the table file.
        let mut out = crate::output::stdout::handle();
        let mut err = std::io::stderr();
        return internal_fetch(
            as_user,
            crate::privilege::is_root(),
            &work_root,
            &download,
            &mut out,
            &mut err,
        );
    }
    let config = match read_config_as_a_run(&cli) {
        Ok(config) => config,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{}", e.message);
            return e.exit_code;
        }
    };
    let location = TableLocation {
        flag: cli.g729_tables.clone(),
        key: config.g729.tables.clone(),
        default: crate::rtp::g729_tables::default_table_file_here(),
    };
    let exe = std::env::current_exe().ok();
    let env = InstallEnv {
        root: crate::privilege::is_root(),
        config_user: config.privilege.user.as_deref(),
        // The capture run's rule for the switch; `sipnab g729` has no
        // `--priv-drop`, and its own `--no-priv-drop` is read in `run`.
        config_no_priv_drop: crate::cli::switch(false, false, config.privilege.no_priv_drop, false),
        work_root: &work_root,
        exe: exe.as_deref(),
    };
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut out = crate::output::stdout::handle();
    let mut err = std::io::stderr();
    let mut io = Io {
        input: &mut input,
        out: &mut out,
        err: &mut err,
    };
    run(&cli.command, &location, &env, &mut io, &download)
}

/// What an install needs to know about the process it runs in, beyond the
/// command line: whether it is root, the `[privilege]` settings, the
/// directory the download is unpacked in, and the binary a child runs.
#[derive(Debug, Clone, Copy)]
pub struct InstallEnv<'a> {
    /// Whether the process is root.
    pub root: bool,
    /// `[privilege] user`.
    pub config_user: Option<&'a str>,
    /// `[privilege] no_priv_drop`.
    pub config_no_priv_drop: bool,
    /// The directory the package is written and unpacked in: `TMPDIR`, else
    /// `/tmp`.
    pub work_root: &'a Path,
    /// The sipnab binary a child of a root install runs, when known.
    pub exe: Option<&'a Path>,
}

/// Read the config file `-f` / `--no-config` name, and check it as a run
/// checks it before reading `[g729] tables` from it: the same loader, which
/// warns about every key it does not know, the same section validators, and
/// the same config-only refusals `-D` makes. A file a run refuses is refused
/// here with the run's message and exit status, so `status` never reports on
/// a file no run would read.
///
/// The warnings go to stderr at the level a headless run logs them.
///
/// # Errors
///
/// The run's `PlanError`.
fn read_config_as_a_run(
    cli: &G729Cli,
) -> Result<crate::config::Config, crate::app::bootstrap::PlanError> {
    use crate::app::bootstrap;
    let mut run = crate::cli::Cli::parse_from_args(["sipnab", "-N", "-q"]);
    run.config_args.config.clone_from(&cli.config);
    run.config_args.no_config = cli.no_config;
    bootstrap::init_logging(&run);
    let loaded =
        bootstrap::read_config(&run).and_then(|read| bootstrap::apply_config(&run, read))?;
    bootstrap::refuse_invalid_config(&run, &loaded.config)?;
    Ok(loaded.config)
}

/// Run one `sipnab g729` command against `location`. Exit codes: 0 done (or
/// installed, for `status`), 1 refused or failed (or not installed).
pub fn run(
    command: &G729Command,
    location: &TableLocation,
    env: &InstallEnv<'_>,
    io: &mut Io<'_>,
    fetch: Fetch<'_>,
) -> i32 {
    let outcome = match command {
        G729Command::Status => return status(location, io.out),
        G729Command::InternalFetch { as_user } => {
            return internal_fetch(as_user, env.root, env.work_root, fetch, io.out, io.err);
        }
        G729Command::Install {
            yes,
            from,
            user,
            no_priv_drop,
        } => {
            let who = fetcher(
                env.root,
                *no_priv_drop || env.config_no_priv_drop,
                user.as_deref(),
                env.config_user,
            );
            install(location, *yes, from.as_deref(), who, env, io, fetch)
        }
    };
    match outcome {
        Ok(Some(done)) => {
            let _ = writeln!(io.out, "{done}");
            0
        }
        Ok(None) => {
            let _ = writeln!(io.err, "Not installed: the answer was not yes.");
            1
        }
        Err(e) => {
            let _ = writeln!(io.err, "{e}");
            1
        }
    }
}

/// `status`: installed or not, the file, and its values hash.
fn status(location: &TableLocation, out: &mut dyn Write) -> i32 {
    let Some(path) = location.path() else {
        let _ = writeln!(
            out,
            "G.729 tables: not installed\nTable file: none (no --g729-tables, no [g729] tables, \
             and neither HOME nor XDG_CONFIG_HOME names a directory)"
        );
        return 1;
    };
    match crate::rtp::g729_tables::load(path) {
        Ok(tables) => {
            let _ = writeln!(
                out,
                "G.729 tables: installed\nTable file: {}\nValues sha256: {}",
                path.display(),
                tables.values_sha256_hex()
            );
            0
        }
        Err(why) => {
            let _ = writeln!(
                out,
                "G.729 tables: not installed\nTable file: {}\n{why}",
                path.display()
            );
            1
        }
    }
}

/// `install`: ask, take the package, build and write the table file.
/// `Ok(None)` when the operator did not answer yes.
fn install(
    location: &TableLocation,
    yes: bool,
    from: Option<&Path>,
    who: Fetcher<'_>,
    env: &InstallEnv<'_>,
    io: &mut Io<'_>,
    fetch: Fetch<'_>,
) -> Result<Option<String>, String> {
    let Some(target) = location.path() else {
        return Err(format!(
            "No place to install {TABLE_FILE_NAME}: give --g729-tables PATH, set [g729] tables, \
             or set HOME"
        ));
    };
    let _ = write!(io.out, "{}", notice(from, target));
    if !consent(yes, io)? {
        return Ok(None);
    }
    let table = match from {
        Some(path) => {
            let table = table_file_from(path)?;
            let _ = writeln!(io.out, "{}", describe_source(path));
            table
        }
        None => download_table(who, env, io, fetch)?,
    };
    write_table_file(target, &table)?;
    let hash = crate::rtp::g729_tables::values_hash(&table).unwrap_or_default();
    Ok(Some(format!(
        "Installed the G.729 tables: {}\nValues sha256: {hash}",
        target.display()
    )))
}

/// Download the package and install the tables at `location`, without asking:
/// for the terminal UI, once the operator has said yes or
/// `[g729] auto_install = true` has.
///
/// # Errors
///
/// No place to install, the download failed, or a refusal naming the
/// expected and the actual hash.
pub fn install_download(location: &TableLocation, fetch: Fetch<'_>) -> Result<String, String> {
    let mut no_input = std::io::empty();
    let mut out = std::io::sink();
    let mut err = std::io::sink();
    let mut io = Io {
        input: &mut no_input,
        out: &mut out,
        err: &mut err,
    };
    // The terminal UI downloads as the user its run dropped to, in this
    // process, as before.
    let work_root = std::env::temp_dir();
    let env = InstallEnv {
        root: false,
        config_user: None,
        config_no_priv_drop: false,
        work_root: &work_root,
        exe: None,
    };
    install(
        location,
        true,
        None,
        Fetcher::ThisProcess,
        &env,
        &mut io,
        fetch,
    )?
    .ok_or_else(|| "Not installed.".to_string())
}

/// What the command prints before it asks: what it reads, what it checks,
/// where it writes, and why.
#[must_use]
pub fn notice(from: Option<&Path>, target: &Path) -> String {
    let what = match from {
        Some(path) => format!(
            "Source: {}. Nothing is downloaded. sipnab reads the ITU-T G.729 (06/2012) Release 3 \
             package zip (its sha256 must be {PACKAGE_SHA256}), a directory extracted from it, \
             or a table file built from it on another host, keeps only the numeric codebook \
             values, and writes them to {}. The source is not changed.",
            path.display(),
            target.display()
        ),
        None => format!(
            "Source: {PACKAGE_URL}. sipnab downloads the ITU-T G.729 (06/2012) Release 3 package \
             ({PACKAGE_BYTES} bytes), checks that its sha256 is {PACKAGE_SHA256}, keeps only the \
             numeric codebook values, writes them to {}, and deletes the download.",
            target.display()
        ),
    };
    format!(
        "sipnab g729 install builds the G.729 decoder's codebook tables.\n\n{what}\n\n{WHY}\n\n"
    )
}

/// The line that says what `--from` read: the kind of source and, for a
/// file, its own sha256.
fn describe_source(path: &Path) -> String {
    if path.is_dir() {
        return format!("Read the extracted package directory {}", path.display());
    }
    let Ok(bytes) = std::fs::read(path) else {
        return format!("Read {}", path.display());
    };
    let kind = if bytes.starts_with(g729::tables::FILE_MAGIC) {
        "the table file"
    } else {
        "the package zip"
    };
    format!("Read {kind} {} (sha256 {})", path.display(), sha256(&bytes))
}

/// Ask once, unless `yes`. Only `y` or `yes` (any case) is yes; anything
/// else, an empty line and the end of input included, is no.
///
/// # Errors
///
/// The answer could not be read.
pub fn consent(yes: bool, io: &mut Io<'_>) -> Result<bool, String> {
    if yes {
        return Ok(true);
    }
    let _ = write!(io.out, "Install the G.729 tables? [y/N] ");
    let _ = io.out.flush();
    let mut answer = String::new();
    io.input
        .read_line(&mut answer)
        .map_err(|e| format!("reading the answer: {e}"))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// sha256 of `bytes`, lowercase hex.
fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

/// The refusal for a package whose hash is not the pinned one.
fn package_refusal(what: &str, actual: &str) -> Result<Vec<u8>, String> {
    Err(format!(
        "Refused {what}: its sha256 is {actual}, expected {PACKAGE_SHA256} (the ITU-T G.729 \
         (06/2012) Release 3 package). Nothing was installed."
    ))
}

/// The table file `--from` names, from whichever of the three forms `path`
/// is: a directory extracted from the package, an existing table file, or the
/// package zip.
///
/// # Errors
///
/// The path cannot be read; a zip whose sha256 is not the pinned one; a
/// table file or a package whose values hash is not the pinned one. Each
/// refusal names the expected and the actual hash.
pub fn table_file_from(path: &Path) -> Result<Vec<u8>, String> {
    if path.is_dir() {
        return import(path);
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => return Err(format!("Cannot read {}: {e}", path.display())),
    };
    if bytes.starts_with(g729::tables::FILE_MAGIC) {
        return match g729::Tables::from_bytes(&bytes) {
            Ok(_) => Ok(bytes),
            Err(e) => table_refusal(path, &bytes, &e),
        };
    }
    let actual = sha256(&bytes);
    if actual != PACKAGE_SHA256 {
        return package_refusal(&path.display().to_string(), &actual);
    }
    import(path)
}

/// The refusal for a table file the loader refused.
fn table_refusal(path: &Path, bytes: &[u8], e: &g729::TableError) -> Result<Vec<u8>, String> {
    match e {
        g729::TableError::ValuesHash => Err(format!(
            "Refused the table file {}: its values sha256 is {}, expected {}. Nothing was \
             installed.",
            path.display(),
            crate::rtp::g729_tables::values_hash(bytes).unwrap_or_else(|| "unknown".into()),
            g729::tables::VALUES_SHA256
        )),
        other => Err(format!(
            "Refused the table file {}: {other}. Nothing was installed.",
            path.display()
        )),
    }
}

/// `g729::import_from_itu` on `path`, its refusal worded for the operator.
fn import(path: &Path) -> Result<Vec<u8>, String> {
    match g729::import_from_itu(path) {
        Ok(table) => Ok(table),
        Err(e) => Err(format!(
            "Refused {}: {e}. Nothing was installed.",
            path.display()
        )),
    }
}

/// Make `dir` and its parents.
fn create_dir(dir: &Path) -> Result<(), String> {
    match std::fs::create_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("Cannot create {}: {e}", dir.display())),
    }
}

/// The table file from a downloaded package: the package's hash is checked
/// first, the bytes go to a temporary file in `dir`, the download's private
/// work directory ([`work_dir`]), for the importer, and that file is deleted
/// whatever happens.
///
/// # Errors
///
/// A package whose sha256 is not the pinned one, a temporary file that cannot
/// be written, or the importer's refusal.
pub fn table_file_from_download(package: Vec<u8>, dir: &Path) -> Result<Vec<u8>, String> {
    let actual = sha256(&package);
    if actual != PACKAGE_SHA256 {
        return package_refusal(&format!("the download from {PACKAGE_URL}"), &actual);
    }
    let written = tempfile::Builder::new()
        .prefix(".sipnab-g729-package-")
        .suffix(".zip")
        .tempfile_in(dir)
        .and_then(|mut temp| {
            temp.write_all(&package)?;
            temp.flush()?;
            Ok(temp)
        });
    let temp = match written {
        Ok(temp) => temp,
        Err(e) => {
            return Err(format!(
                "Cannot write the download in {}: {e}",
                dir.display()
            ));
        }
    };
    drop(package);
    // `temp` is deleted when it goes out of scope, on every path.
    import(temp.path())
}

/// The directory `target` is written in.
fn target_dir(target: &Path) -> PathBuf {
    match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Write `table` to `target` by an atomic rename, readable by every user
/// (0644): the tables are not secret, and a service account must read them.
///
/// # Errors
///
/// The directory cannot be made or the file cannot be written.
pub fn write_table_file(target: &Path, table: &[u8]) -> Result<(), String> {
    create_dir(&target_dir(target))?;
    if let Err(e) = crate::capture::atomic::write_atomic(target, |w| w.write_all(table)) {
        return Err(format!("Cannot write {}: {e}", target.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o644)) {
            return Err(format!("Cannot set the mode of {}: {e}", target.display()));
        }
    }
    Ok(())
}

/// The command name the refusals and warnings of a root install give.
const COMMAND: &str = "sipnab g729 install";

/// Who downloads and unpacks the package (G729-INSTALL-DOWNLOADS-AS-ROOT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetcher<'a> {
    /// This process, as it is: not root, so it has nothing to shed.
    ThisProcess,
    /// This process, as root, because `--no-priv-drop` or
    /// `[privilege] no_priv_drop` said so; one warning line says it.
    ThisProcessKeptRoot,
    /// A child process started as this user. Only the install of the table
    /// file it sends back runs as root.
    Child(&'a str),
}

/// Who downloads and unpacks the package for an install started with
/// these settings.
///
/// Root drops to `--user`, else `[privilege] user`, else `nobody`, on every
/// platform: a download needs no user session, so the macOS exception of a
/// capture run does not apply.
#[must_use]
pub fn fetcher<'a>(
    root: bool,
    no_priv_drop: bool,
    flag_user: Option<&'a str>,
    config_user: Option<&'a str>,
) -> Fetcher<'a> {
    if !root {
        return Fetcher::ThisProcess;
    }
    if no_priv_drop {
        return Fetcher::ThisProcessKeptRoot;
    }
    Fetcher::Child(
        flag_user
            .or(config_user)
            .unwrap_or(crate::privilege::DEFAULT_DROP_USER),
    )
}

/// The need the download has: to write in `work_root`, `TMPDIR`.
#[must_use]
pub fn work_need(work_root: &Path) -> crate::early_exit::Need {
    crate::early_exit::Need {
        path: work_root.to_path_buf(),
        what: "TMPDIR",
        access: crate::early_exit::Access::WriteDir,
    }
}

/// The refusal of a download run as `user` that cannot write in
/// `work_root`, in the words of every command that drops
/// ([`crate::early_exit::refusal`]).
#[must_use]
pub fn work_refusal(work_root: &Path, user: &str) -> String {
    let need = work_need(work_root);
    let sudo_user = std::env::var("SUDO_USER").ok();
    let offer = crate::early_exit::sudo_user_offer(sudo_user.as_deref(), user, |other| {
        crate::early_exit::user_can(other, &need)
    });
    crate::early_exit::refusal(COMMAND, &need, user, offer)
}

/// A new private directory under `work_root` for the download, deleted when
/// it is dropped.
///
/// # Errors
///
/// The directory cannot be made: for a download run as `user`, the
/// [`work_refusal`]; else a line naming the directory and the error.
pub fn work_dir(work_root: &Path, user: Option<&str>) -> Result<tempfile::TempDir, String> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".sipnab-g729-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir_in(work_root).map_err(|e| match user {
        Some(user) => work_refusal(work_root, user),
        None => format!(
            "Cannot make a work directory for the download in {} (TMPDIR): {e}. Set TMPDIR to \
             a directory you can write in. Nothing was installed.",
            work_root.display()
        ),
    })
}

/// The arguments a child of a root install runs the sipnab binary with. The
/// user goes in the same argument as its flag, so a name that starts with a
/// dash is still its value.
#[must_use]
pub fn child_args(user: &str) -> Vec<String> {
    vec![
        "g729".into(),
        "internal-fetch".into(),
        format!("--as-user={user}"),
    ]
}

/// Read what the child sent: the table file, at most `limit` bytes.
///
/// # Errors
///
/// The pipe failed, or the child sent more than `limit` bytes.
pub fn read_answer(
    reader: &mut dyn std::io::Read,
    user: &str,
    limit: usize,
) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut answer = Vec::new();
    let bound = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    reader
        .take(bound)
        .read_to_end(&mut answer)
        .map_err(|e| format!("{COMMAND}: reading the download as user '{user}': {e}"))?;
    if answer.len() > limit {
        return Err(format!(
            "{COMMAND}: the download as user '{user}' sent more than {limit} bytes, more than a \
             table file. Nothing was installed."
        ));
    }
    Ok(answer)
}

/// The table file a child run as `user` sent, once it ended with `code`
/// (`None` when a signal ended it), checked as `--from` checks a table file.
///
/// # Errors
///
/// The child did not end with 0, or the bytes are not a table file the
/// loader accepts.
pub fn child_table(user: &str, code: Option<i32>, answer: Vec<u8>) -> Result<Vec<u8>, String> {
    match code {
        Some(0) => {}
        Some(code) => {
            return Err(format!(
                "{COMMAND}: the download as user '{user}' failed (exit {code}); its reason is \
                 above. Nothing was installed."
            ));
        }
        None => {
            return Err(format!(
                "{COMMAND}: the download as user '{user}' was ended by a signal. Nothing was \
                 installed."
            ));
        }
    }
    match g729::Tables::from_bytes(&answer) {
        Ok(_) => Ok(answer),
        Err(e) => table_refusal(
            Path::new(&format!("sent by the download as user '{user}'")),
            &answer,
            &e,
        ),
    }
}

/// Download and unpack the package as `who` says, and return the table file.
///
/// # Errors
///
/// The work directory, the download, the package or the child failed; each
/// error says which.
///
/// # Side effects
///
/// Prints progress on `io.out` and a kept-root warning on `io.err`; makes a
/// connection, here or in a child process it starts and waits for.
fn download_table(
    who: Fetcher<'_>,
    env: &InstallEnv<'_>,
    io: &mut Io<'_>,
    fetch: Fetch<'_>,
) -> Result<Vec<u8>, String> {
    let user = match who {
        Fetcher::Child(user) => user,
        Fetcher::ThisProcess | Fetcher::ThisProcessKeptRoot => {
            if who == Fetcher::ThisProcessKeptRoot {
                let _ = writeln!(io.err, "{}", crate::early_exit::kept_root_warning(COMMAND));
            }
            let dir = work_dir(env.work_root, None)?;
            let _ = writeln!(io.out, "Downloading {PACKAGE_URL} ...");
            let package = fetch(PACKAGE_URL)?;
            let _ = writeln!(io.out, "{}", read_line(&package));
            return table_file_from_download(package, dir.path());
        }
    };
    // Everything that can be refused is refused here, as root, before a
    // child starts or a connection is made.
    crate::privilege::resolve_user(user)
        .map_err(|e| format!("{COMMAND}: no user '{user}' to download as: {e:#}"))?;
    if !crate::early_exit::user_can(user, &work_need(env.work_root)) {
        return Err(work_refusal(env.work_root, user));
    }
    let exe = env.exe.ok_or_else(|| {
        format!(
            "{COMMAND}: cannot find the sipnab binary to download as user '{user}' with; pass \
             --no-priv-drop to download as root. Nothing was installed."
        )
    })?;
    let _ = writeln!(io.out, "Downloading {PACKAGE_URL} as user '{user}' ...");
    fetch_in_child(exe, user)
}

/// The line that says what was downloaded.
fn read_line(package: &[u8]) -> String {
    format!(
        "Read {PACKAGE_URL} ({} bytes, sha256 {})",
        package.len(),
        sha256(package)
    )
}

/// Run `sipnab g729 internal-fetch` as `user`, from `exe`, and return the
/// table file it sends.
///
/// # Errors
///
/// The user does not exist, the child cannot be started, or what
/// [`read_answer`] and [`child_table`] refuse.
///
/// # Side effects
///
/// Starts a child process with the user's ids, its standard error going to
/// this process's, and waits for it.
#[cfg(unix)]
fn fetch_in_child(exe: &Path, user: &str) -> Result<Vec<u8>, String> {
    use std::os::unix::process::CommandExt as _;
    let (uid, gid) = crate::privilege::resolve_user(user)
        .map_err(|e| format!("{COMMAND}: no user '{user}' to download as: {e:#}"))?;
    let mut child = std::process::Command::new(exe)
        .args(child_args(user))
        .uid(uid)
        .gid(gid)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| spawn_refusal(exe, user, &e))?;
    let answer = match child.stdout.take() {
        Some(mut out) => read_answer(&mut out, user, g729::FILE_LEN),
        None => Err(format!(
            "{COMMAND}: the download as user '{user}' has no output"
        )),
    };
    if answer.is_err() {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|e| format!("{COMMAND}: waiting for the download as user '{user}': {e}"))?;
    child_table(user, status.code(), answer?)
}

/// A build for a platform without unix user ids has no child to drop in.
#[cfg(not(unix))]
fn fetch_in_child(_exe: &Path, user: &str) -> Result<Vec<u8>, String> {
    Err(format!(
        "{COMMAND}: this platform cannot start the download as user '{user}'; pass \
         --no-priv-drop to download as this user. Nothing was installed."
    ))
}

/// The refusal of a child that could not be started.
#[cfg(unix)]
fn spawn_refusal(exe: &Path, user: &str, e: &std::io::Error) -> String {
    format!(
        "{COMMAND}: cannot start the download as user '{user}': {e}. '{user}' must be able to \
         run {}; choose one: install sipnab where '{user}' can run it; run it with --user USER, \
         naming a user who can; or pass --no-priv-drop to keep root. Nothing was installed.",
        exe.display()
    )
}

/// `sipnab g729 internal-fetch`: the child of an install started as root.
/// Makes its work directory, downloads the package, checks and unpacks it,
/// and writes the table file to `out`.
///
/// # Returns
///
/// The exit code: 0 sent, 1 failed (the reason on `err`), 2 refused because
/// it was started as root.
pub fn internal_fetch(
    as_user: &str,
    root: bool,
    work_root: &Path,
    fetch: Fetch<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    if root {
        let _ = writeln!(
            err,
            "sipnab g729 internal-fetch: refused: started as root. `{COMMAND}` starts this \
             command as the user it drops to; run `{COMMAND}` instead."
        );
        return 2;
    }
    let outcome = work_dir(work_root, Some(as_user)).and_then(|dir| {
        let package = fetch(PACKAGE_URL)?;
        let _ = writeln!(err, "{}", read_line(&package));
        table_file_from_download(package, dir.path())
    });
    match outcome {
        Ok(table) => match out.write_all(&table).and_then(|()| out.flush()) {
            Ok(()) => 0,
            Err(e) => {
                let _ = writeln!(err, "{COMMAND}: sending the table file: {e}");
                1
            }
        },
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

/// The package, downloaded over HTTPS with the shared client in
/// [`crate::app::https_client`], trusting the host's CA bundle, at most
/// [`PACKAGE_BYTES`]. Every build with `g729` has it, the static musl builds
/// included.
///
/// # Errors
///
/// No connection, a refused certificate, an answer other than 200, or more
/// bytes than the package holds.
pub fn download(url: &str) -> Result<Vec<u8>, String> {
    use crate::app::https_client::{
        Endpoint, client_config, exchange, read_body, read_head, status_of,
    };
    const TRUST: crate::tls_files::TrustNames<'static> = crate::tls_files::TrustNames {
        ca: "SSL_CERT_FILE",
        extra: "SSL_CERT_FILE",
        issuer: "itu.int's CA",
    };
    // Quoted with its userinfo redacted, as `Endpoint::parse` quotes it:
    // credentials in the URL are refused precisely so they never reach the
    // log.
    let shown = crate::app::run_provenance::redact_url_userinfo(url);
    let endpoint = Endpoint::parse(url, crate::app::https_client::UrlUse::DOWNLOAD)
        .map_err(|e| format!("{shown}: {e}"))?;
    let config = client_config(None, None, &TRUST)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: sipnab/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        endpoint.target,
        endpoint.host_header(),
        env!("CARGO_PKG_VERSION")
    );
    let fetched = exchange(
        &endpoint,
        std::time::Duration::from_secs(60),
        Some(&config),
        request.as_bytes(),
        |reader| {
            let head = read_head(reader, 64 * 1024, "the download's header limit")?;
            let status = status_of(&head)?;
            if status != 200 {
                return Err(format!("itu.int answered {status}"));
            }
            let (body, more) = read_body(reader, &head, PACKAGE_BYTES)?;
            if more {
                return Err(format!(
                    "itu.int answered more than {PACKAGE_BYTES} bytes, more than the package"
                ));
            }
            Ok(body)
        },
    );
    match fetched {
        Ok(body) => Ok(body),
        Err(e) => Err(format!("Downloading {url} failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::g729_tables::test_support;

    type TestError = Box<dyn std::error::Error>;

    /// What one run wrote, and its exit code.
    struct Ran {
        code: i32,
        out: String,
        err: String,
    }

    /// The network is never reached from a test: this stand-in fails the
    /// test if anything asks it to fetch.
    fn no_network(url: &str) -> Result<Vec<u8>, String> {
        Err(format!("a test tried to download {url}"))
    }

    /// Serve `answer` once on a loopback port and return the URL that
    /// reaches it.
    fn serve_once(answer: Vec<u8>) -> Result<String, TestError> {
        use std::io::{BufRead, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = std::io::BufReader::new(stream);
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                line.clear();
            }
            let _ = reader.get_mut().write_all(&answer);
        });
        Ok(format!("http://127.0.0.1:{port}/package.zip"))
    }

    /// Every build with `g729` downloads, the static musl builds included:
    /// the client is the shared one in `https_client`, not the vCon
    /// forwarder's, so a build without `vcon` has it too.
    ///
    /// Driven over plain HTTP on loopback because a test cannot reach
    /// itu.int; the TLS layer is the same rustls configuration the vCon
    /// forwarder's tests drive.
    #[test]
    fn the_download_needs_no_vcon_feature() -> Result<(), TestError> {
        let body = b"the package bytes".to_vec();
        let mut answer =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        answer.extend_from_slice(&body);
        let url = serve_once(answer)?;
        assert_eq!(download(&url)?, body);
        Ok(())
    }

    /// An answer other than 200 is refused with its status, whatever the
    /// build.
    #[test]
    fn a_download_answered_other_than_200_is_refused() -> Result<(), TestError> {
        let url = serve_once(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec())?;
        let err = download(&url).err().ok_or("a 404 is refused")?;
        assert!(err.contains("404"), "{err}");
        Ok(())
    }

    fn run_with(command: &G729Command, target: &Path, answer: &str, fetch: Fetch<'_>) -> Ran {
        let work_root = std::env::temp_dir();
        let env = InstallEnv {
            root: false,
            config_user: None,
            config_no_priv_drop: false,
            work_root: &work_root,
            exe: None,
        };
        run_in(command, target, answer, fetch, &env)
    }

    /// [`run_with`] in the process `env` describes.
    fn run_in(
        command: &G729Command,
        target: &Path,
        answer: &str,
        fetch: Fetch<'_>,
        env: &InstallEnv<'_>,
    ) -> Ran {
        let location = TableLocation {
            flag: Some(target.to_path_buf()),
            key: None,
            default: None,
        };
        let mut input = std::io::Cursor::new(answer.as_bytes().to_vec());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            command,
            &location,
            env,
            &mut Io {
                input: &mut input,
                out: &mut out,
                err: &mut err,
            },
            fetch,
        );
        Ran {
            code,
            out: String::from_utf8_lossy(&out).into_owned(),
            err: String::from_utf8_lossy(&err).into_owned(),
        }
    }

    fn install_from(from: &Path, yes: bool) -> G729Command {
        G729Command::Install {
            yes,
            from: Some(from.to_path_buf()),
            user: None,
            no_priv_drop: false,
        }
    }

    /// The notice names the package by its URL and hash, as PROVENANCE.md
    /// records them, and links that file for the verbatim notices.
    #[test]
    fn the_notice_matches_provenance_md() -> Result<(), TestError> {
        let provenance = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/g729/PROVENANCE.md"),
        )?;
        assert!(provenance.contains(PACKAGE_URL));
        assert!(provenance.contains(PACKAGE_SHA256));
        assert!(WHY.contains("crates/g729/PROVENANCE.md"));
        Ok(())
    }

    /// Installing from the fetched package's extracted directory, with
    /// `--yes`, writes a table file the loader accepts, mode 0644, and
    /// touches no network.
    #[test]
    fn install_from_the_extracted_package_writes_the_tables() -> Result<(), TestError> {
        let package = test_support::package_dir()?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("sub").join(TABLE_FILE_NAME);
        let ran = run_with(&install_from(&package, true), &target, "", &no_network);
        assert_eq!(ran.code, 0, "{}{}", ran.out, ran.err);
        assert!(
            ran.out.contains(&format!(
                "Read the extracted package directory {}",
                package.display()
            )),
            "{}",
            ran.out
        );
        assert!(ran.out.contains(g729::tables::VALUES_SHA256), "{}", ran.out);
        let tables = crate::rtp::g729_tables::load(&target)?;
        assert_eq!(tables.values_sha256_hex(), g729::tables::VALUES_SHA256);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&target)?.permissions().mode() & 0o777,
                0o644
            );
        }
        let litter: Vec<_> = std::fs::read_dir(target_dir(&target))?
            .filter_map(Result::ok)
            .filter(|e| e.file_name() != TABLE_FILE_NAME)
            .collect();
        assert!(litter.is_empty(), "left behind: {litter:?}");
        Ok(())
    }

    /// `--from` downloads nothing and deletes nothing, and the notice says
    /// so instead of describing a download.
    #[test]
    fn the_notice_for_from_describes_no_download() {
        let notice = notice(
            Some(Path::new("/srv/g729.zip")),
            Path::new("/t/g729-tables.bin"),
        );
        assert!(notice.contains("Nothing is downloaded"), "{notice}");
        assert!(!notice.contains("deletes the download"), "{notice}");
        assert!(!notice.contains("Package sha256:"), "{notice}");
        let download = notice_for_download();
        assert!(download.contains(PACKAGE_URL), "{download}");
        assert!(download.contains("deletes the download"), "{download}");
    }

    /// The notice for a download, for the test above.
    fn notice_for_download() -> String {
        notice(None, Path::new("/t/g729-tables.bin"))
    }

    /// A table file installs saying what it read and that file's own
    /// sha256, not the package's.
    #[test]
    fn install_from_a_table_file_names_it_and_its_own_hash() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let bytes = test_support::table_file()?.to_vec();
        let file = dir.path().join("from-other-host.bin");
        std::fs::write(&file, &bytes)?;
        let target = dir.path().join("installed").join(TABLE_FILE_NAME);
        let ran = run_with(&install_from(&file, true), &target, "", &no_network);
        assert_eq!(ran.code, 0, "{}", ran.err);
        let read = format!(
            "Read the table file {} (sha256 {})",
            file.display(),
            sha256(&bytes)
        );
        assert!(ran.out.contains(&read), "{}", ran.out);
        // The pinned package hash may appear as what a zip must have, never
        // as this file's hash.
        assert!(!ran.out.contains("Package sha256:"), "{}", ran.out);
        Ok(())
    }

    /// Without `--yes`, a "y" installs; anything else refuses and writes
    /// nothing.
    #[test]
    fn the_question_must_be_answered_yes() -> Result<(), TestError> {
        let package = test_support::package_dir()?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join(TABLE_FILE_NAME);
        for answer in ["", "\n", "n\n", "no\n", "yess\n"] {
            let ran = run_with(&install_from(&package, false), &target, answer, &no_network);
            assert_eq!(ran.code, 1, "{answer:?}");
            assert!(ran.out.contains("[y/N]"), "{answer:?}: {}", ran.out);
            assert!(ran.err.contains("not yes"), "{answer:?}: {}", ran.err);
            assert!(!target.exists(), "{answer:?} installed");
        }
        let ran = run_with(&install_from(&package, false), &target, "Y\n", &no_network);
        assert_eq!(ran.code, 0, "{}", ran.err);
        assert!(target.is_file());
        Ok(())
    }

    /// A zip that is not the pinned package is refused before it is read,
    /// naming the expected and the actual sha256.
    #[test]
    fn a_zip_with_another_hash_is_refused_naming_both_hashes() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let zip = dir.path().join("package.zip");
        let bytes = b"PK\x03\x04 not the ITU-T package".to_vec();
        std::fs::write(&zip, &bytes)?;
        let target = dir.path().join(TABLE_FILE_NAME);
        let ran = run_with(&install_from(&zip, true), &target, "", &no_network);
        assert_eq!(ran.code, 1);
        assert!(ran.err.contains(PACKAGE_SHA256), "{}", ran.err);
        assert!(ran.err.contains(&sha256(&bytes)), "{}", ran.err);
        assert!(!target.exists());
        Ok(())
    }

    /// A table file from another host installs as it is; one whose values
    /// differ is refused naming both values hashes.
    #[test]
    fn a_table_file_installs_and_an_altered_one_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let good = dir.path().join("from-other-host.bin");
        std::fs::write(&good, test_support::table_file()?)?;
        let target = dir.path().join("installed").join(TABLE_FILE_NAME);
        let ran = run_with(&install_from(&good, true), &target, "", &no_network);
        assert_eq!(ran.code, 0, "{}", ran.err);
        assert_eq!(std::fs::read(&target)?, test_support::table_file()?);

        let mut altered = test_support::table_file()?.to_vec();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        let bad = dir.path().join("altered.bin");
        std::fs::write(&bad, &altered)?;
        let other = dir.path().join("other").join(TABLE_FILE_NAME);
        let ran = run_with(&install_from(&bad, true), &other, "", &no_network);
        assert_eq!(ran.code, 1);
        let actual = crate::rtp::g729_tables::values_hash(&altered).ok_or("valid layout")?;
        assert!(ran.err.contains(&actual), "{}", ran.err);
        assert!(ran.err.contains(g729::tables::VALUES_SHA256), "{}", ran.err);
        assert!(!other.exists());
        Ok(())
    }

    /// The download path: what comes back from the URL is checked against
    /// the pinned package hash before anything is written, and the temporary
    /// copy is gone afterwards.
    ///
    /// The wire itself is unreachable here: a test must not download 18 MB
    /// from itu.int, and a CI runner may have no route to it. So the fetch is
    /// a stand-in that returns bytes, and what is tested is the conversion
    /// the download feeds: hash check, temporary file, import, cleanup. The
    /// real package's conversion is the `--from` zip path, which calls the
    /// same importer on the same file form.
    #[test]
    fn a_download_with_another_hash_is_refused_and_leaves_nothing() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join(TABLE_FILE_NAME);
        let served = b"<html>a login page, not the package</html>".to_vec();
        let expected_actual = sha256(&served);
        let fetch = move |url: &str| -> Result<Vec<u8>, String> {
            assert_eq!(url, PACKAGE_URL);
            Ok(served.clone())
        };
        let command = G729Command::Install {
            yes: true,
            from: None,
            user: None,
            no_priv_drop: false,
        };
        let ran = run_with(&command, &target, "", &fetch);
        assert_eq!(ran.code, 1);
        assert!(ran.out.contains(PACKAGE_URL), "{}", ran.out);
        assert!(ran.err.contains(PACKAGE_SHA256), "{}", ran.err);
        assert!(ran.err.contains(&expected_actual), "{}", ran.err);
        assert_eq!(std::fs::read_dir(dir.path())?.count(), 0, "nothing written");
        Ok(())
    }

    /// The download is not attempted until the question is answered yes.
    #[test]
    fn no_download_without_consent() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join(TABLE_FILE_NAME);
        let command = G729Command::Install {
            yes: false,
            from: None,
            user: None,
            no_priv_drop: false,
        };
        let ran = run_with(&command, &target, "n\n", &no_network);
        assert_eq!(ran.code, 1);
        assert!(ran.out.contains(PACKAGE_URL), "{}", ran.out);
        assert!(!ran.err.contains("a test tried to download"), "{}", ran.err);
        Ok(())
    }

    /// `status` says not installed, then installed with the path and the
    /// values hash.
    #[test]
    fn status_reports_the_file_and_its_values_hash() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join(TABLE_FILE_NAME);
        let ran = run_with(&G729Command::Status, &target, "", &no_network);
        assert_eq!(ran.code, 1);
        assert!(ran.out.contains("not installed"), "{}", ran.out);
        assert!(
            ran.out.contains(&target.display().to_string()),
            "{}",
            ran.out
        );
        std::fs::write(&target, test_support::table_file()?)?;
        let ran = run_with(&G729Command::Status, &target, "", &no_network);
        assert_eq!(ran.code, 0, "{}", ran.out);
        assert!(ran.out.contains("installed"), "{}", ran.out);
        assert!(
            ran.out.contains(&target.display().to_string()),
            "{}",
            ran.out
        );
        assert!(ran.out.contains(g729::tables::VALUES_SHA256), "{}", ran.out);
        Ok(())
    }

    /// URL-CREDS-IN-LOGS: a package URL carrying credentials is refused
    /// before any connection, and the refusal must not print them.
    #[test]
    fn t_negative_a_package_url_refusal_never_quotes_the_password() -> Result<(), TestError> {
        let why = download("https://fetcher:s3cret-token@example.invalid/pkg.zip")
            .err()
            .ok_or("a URL with credentials is refused")?;
        assert!(!why.contains("s3cret-token"), "{why}");
        Ok(())
    }

    /// The refusal still names the URL, userinfo redacted.
    #[test]
    fn t_positive_a_package_url_refusal_still_names_the_host() -> Result<(), TestError> {
        let why = download("https://fetcher:s3cret-token@example.invalid/pkg.zip")
            .err()
            .ok_or("refused")?;
        assert!(why.contains("example.invalid/pkg.zip"), "{why}");
        Ok(())
    }

    /// A password with an unescaped `?` leaks neither half.
    #[test]
    fn t_edge_a_package_password_holding_a_question_mark_does_not_leak() -> Result<(), TestError> {
        let why = download("https://fetcher:ab?cd-secret@example.invalid/pkg.zip")
            .err()
            .ok_or("refused")?;
        assert!(
            !why.contains("ab?cd") && !why.contains("cd-secret"),
            "{why}"
        );
        Ok(())
    }

    /// An install started as root downloads and unpacks the package as
    /// another user (G729-INSTALL-DOWNLOADS-AS-ROOT).
    ///
    /// These run as the test's own user, never as root: whether the process
    /// is root is a field of [`InstallEnv`], so the decision and every
    /// refusal before the child starts can be driven here. The child itself
    /// (its uid, its refusal as root, its work directory as the drop user)
    /// is driven as root by tests/g729_install_drop_test.rs.
    mod drops {
        use super::*;
        use std::os::unix::fs::PermissionsExt as _;

        /// A user no host has.
        const NO_SUCH_USER: &str = "sipnab-test-no-such-user";

        /// A sipnab binary no host has, for a child that cannot start.
        const NO_SUCH_EXE: &str = "/nonexistent/sipnab-test/sipnab";

        fn install(user: Option<&str>, no_priv_drop: bool) -> G729Command {
            G729Command::Install {
                yes: true,
                from: None,
                user: user.map(str::to_string),
                no_priv_drop,
            }
        }

        fn env<'a>(root: bool, work_root: &'a Path, exe: Option<&'a Path>) -> InstallEnv<'a> {
            InstallEnv {
                root,
                config_user: None,
                config_no_priv_drop: false,
                work_root,
                exe,
            }
        }

        /// A directory this user can list but not write in.
        fn read_only_dir() -> Result<tempfile::TempDir, TestError> {
            let dir = tempfile::tempdir()?;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))?;
            Ok(dir)
        }

        /// Give `dir` back its write bit, so its `TempDir` can remove it.
        fn writable_again(dir: &tempfile::TempDir) -> Result<(), TestError> {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
            Ok(())
        }

        /// A fetch that hands back bytes that are not the package.
        fn not_the_package(url: &str) -> Result<Vec<u8>, String> {
            assert_eq!(url, PACKAGE_URL, "the fetch is asked for the package URL");
            Ok(b"not the ITU-T package".to_vec())
        }

        /// A fetch that fails.
        fn unreachable(url: &str) -> Result<Vec<u8>, String> {
            Err(format!("Downloading {url} failed: no route (test)"))
        }

        /// A reader whose read fails.
        struct Broken;

        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("the pipe broke (test)"))
            }
        }

        fn entries(dir: &Path) -> Result<usize, TestError> {
            Ok(std::fs::read_dir(dir)?.count())
        }

        // ---- who downloads: success ----

        /// Success: root with no user named downloads as `nobody`.
        #[test]
        fn root_with_no_user_downloads_as_nobody() {
            assert_eq!(
                fetcher(true, false, None, None),
                Fetcher::Child("nobody"),
                "the default drop user"
            );
        }

        /// Success: `--user` names the child's user.
        #[test]
        fn root_downloads_as_the_flag_user() {
            assert_eq!(
                fetcher(true, false, Some("sipnab"), None),
                Fetcher::Child("sipnab"),
                "--user"
            );
        }

        /// Success: `[privilege] user` names it when `--user` is absent.
        #[test]
        fn root_downloads_as_the_config_user() {
            assert_eq!(
                fetcher(true, false, None, Some("svc")),
                Fetcher::Child("svc"),
                "[privilege] user"
            );
        }

        /// Success: `--user` is read before the config file's user.
        #[test]
        fn the_flag_user_wins_over_the_config_user() {
            assert_eq!(
                fetcher(true, false, Some("sipnab"), Some("svc")),
                Fetcher::Child("sipnab"),
                "--user first"
            );
        }

        /// Success: a process that is not root downloads itself.
        #[test]
        fn a_process_that_is_not_root_downloads_itself() {
            assert_eq!(
                fetcher(false, false, None, None),
                Fetcher::ThisProcess,
                "nothing to shed"
            );
        }

        /// Success: a user named to a process that is not root changes
        /// nothing.
        #[test]
        fn a_user_named_to_a_process_that_is_not_root_changes_nothing() {
            assert_eq!(
                fetcher(false, false, Some("sipnab"), Some("svc")),
                Fetcher::ThisProcess,
                "not root: no drop"
            );
        }

        // ---- who downloads: root kept ----

        /// Failure of the drop by request: `--no-priv-drop` keeps root.
        #[test]
        fn no_priv_drop_keeps_root() {
            assert_eq!(
                fetcher(true, true, None, None),
                Fetcher::ThisProcessKeptRoot,
                "--no-priv-drop"
            );
        }

        /// Failure of the drop by request: `--no-priv-drop` wins over a
        /// named user.
        #[test]
        fn no_priv_drop_wins_over_a_named_user() {
            assert_eq!(
                fetcher(true, true, Some("sipnab"), Some("svc")),
                Fetcher::ThisProcessKeptRoot,
                "--no-priv-drop with --user"
            );
        }

        /// Edge: `--no-priv-drop` without root asks for nothing.
        #[test]
        fn no_priv_drop_without_root_is_this_process() {
            assert_eq!(
                fetcher(false, true, None, None),
                Fetcher::ThisProcess,
                "no root to keep, no warning"
            );
        }

        /// Edge: an empty `--user` is passed on and refused when looked up.
        #[test]
        fn an_empty_user_is_passed_on() {
            assert_eq!(
                fetcher(true, false, Some(""), None),
                Fetcher::Child(""),
                "the lookup refuses it"
            );
        }

        /// Edge: naming `nobody` is the same as naming no one.
        #[test]
        fn naming_nobody_is_the_default() {
            assert_eq!(
                fetcher(true, false, Some("nobody"), None),
                fetcher(true, false, None, None),
                "nobody either way"
            );
        }

        // ---- the work directory ----

        /// Success: the need is to write in TMPDIR.
        #[test]
        fn the_need_is_to_write_in_tmpdir() {
            let need = work_need(Path::new("/var/tmp"));
            assert_eq!(need.path, Path::new("/var/tmp"), "the path");
            assert_eq!(need.what, "TMPDIR", "the setting named");
            assert_eq!(
                need.access,
                crate::early_exit::Access::WriteDir,
                "write in it"
            );
        }

        /// Success: the work directory is made inside the root and goes with
        /// its handle.
        #[test]
        fn the_work_directory_is_private_and_removed() -> Result<(), TestError> {
            let root = tempfile::tempdir()?;
            let dir = work_dir(root.path(), None)?;
            assert_eq!(dir.path().parent(), Some(root.path()), "inside TMPDIR");
            let mode = std::fs::metadata(dir.path())?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "only its user reads it");
            drop(dir);
            assert_eq!(entries(root.path())?, 0, "removed with its handle");
            Ok(())
        }

        /// Edge: two downloads get two directories.
        #[test]
        fn two_work_directories_are_distinct() -> Result<(), TestError> {
            let root = tempfile::tempdir()?;
            let first = work_dir(root.path(), None)?;
            let second = work_dir(root.path(), None)?;
            assert_ne!(first.path(), second.path(), "one per download");
            Ok(())
        }

        /// Failure: a TMPDIR this process cannot write in names itself.
        #[test]
        fn an_unwritable_tmpdir_is_named() -> Result<(), TestError> {
            if !crate::test_prereq::not_root(crate::privilege::is_root()) {
                // Root writes in a mode-0500 directory; the root case is
                // tests/g729_install_drop_test.rs.
                return Ok(());
            }
            let root = read_only_dir()?;
            let why = work_dir(root.path(), None)
                .err()
                .ok_or("an unwritable TMPDIR is refused")?;
            writable_again(&root)?;
            assert!(
                why.contains(&root.path().display().to_string()),
                "names the directory: {why}"
            );
            assert!(why.contains("TMPDIR"), "names the setting: {why}");
            Ok(())
        }

        /// Failure: as the drop user, the refusal is the one every dropping
        /// command gives.
        #[test]
        fn an_unwritable_tmpdir_as_the_drop_user_is_the_drop_refusal() -> Result<(), TestError> {
            if !crate::test_prereq::not_root(crate::privilege::is_root()) {
                return Ok(());
            }
            let root = read_only_dir()?;
            let why = work_dir(root.path(), Some("nobody"))
                .err()
                .ok_or("refused")?;
            writable_again(&root)?;
            assert!(
                why.contains("started as root, this command runs as user 'nobody'"),
                "the drop refusal: {why}"
            );
            assert!(why.contains("cannot write in"), "the access: {why}");
            assert!(why.contains("(TMPDIR)"), "the setting: {why}");
            assert!(why.contains("--no-priv-drop"), "the way out: {why}");
            Ok(())
        }

        /// Failure: a TMPDIR that does not exist.
        #[test]
        fn a_missing_tmpdir_is_refused() -> Result<(), TestError> {
            let root = tempfile::tempdir()?;
            let missing = root.path().join("missing");
            let why = work_dir(&missing, None).err().ok_or("refused")?;
            assert!(
                why.contains(&missing.display().to_string()),
                "names it: {why}"
            );
            Ok(())
        }

        /// Edge: a TMPDIR that is a file.
        #[test]
        fn a_tmpdir_that_is_a_file_is_refused() -> Result<(), TestError> {
            let root = tempfile::tempdir()?;
            let file = root.path().join("file");
            std::fs::write(&file, b"x")?;
            assert!(work_dir(&file, None).is_err(), "a file is not a TMPDIR");
            Ok(())
        }

        /// Edge: the refusal names the directory as given.
        #[test]
        fn the_refusal_quotes_the_directory() {
            let why = work_refusal(Path::new("/srv/no-such-tmp"), "nobody");
            assert!(why.contains("'/srv/no-such-tmp'"), "quoted path: {why}");
            assert!(why.starts_with(COMMAND), "the command first: {why}");
        }

        // ---- the child's arguments ----

        /// Success: the child runs the hidden command as the named user.
        #[test]
        fn the_child_runs_internal_fetch_as_the_user() {
            assert_eq!(
                child_args("nobody"),
                ["g729", "internal-fetch", "--as-user=nobody"],
                "the child's arguments"
            );
        }

        /// Success: the arguments parse back to the hidden command.
        #[test]
        fn the_child_arguments_parse() -> Result<(), TestError> {
            use clap::Parser as _;
            let args = std::iter::once("sipnab g729".to_string())
                .chain(child_args("svc").into_iter().skip(1));
            let cli = G729Cli::try_parse_from(args)?;
            assert!(
                matches!(cli.command, G729Command::InternalFetch { ref as_user } if as_user == "svc"),
                "parsed: {:?}",
                cli.command
            );
            Ok(())
        }

        /// Edge: a user whose name starts with a dash still parses as the
        /// value.
        #[test]
        fn a_dash_user_parses_as_the_value() -> Result<(), TestError> {
            use clap::Parser as _;
            let args = std::iter::once("sipnab g729".to_string())
                .chain(child_args("-x").into_iter().skip(1));
            let cli = G729Cli::try_parse_from(args)?;
            assert!(
                matches!(cli.command, G729Command::InternalFetch { ref as_user } if as_user == "-x"),
                "parsed: {:?}",
                cli.command
            );
            Ok(())
        }

        /// Success: `--user` and `--no-priv-drop` parse on `install`.
        #[test]
        fn install_takes_user_and_no_priv_drop() -> Result<(), TestError> {
            use clap::Parser as _;
            let cli = G729Cli::try_parse_from([
                "sipnab g729",
                "install",
                "--user",
                "svc",
                "--no-priv-drop",
            ])?;
            assert!(
                matches!(
                    cli.command,
                    G729Command::Install { ref user, no_priv_drop: true, .. } if user.as_deref() == Some("svc")
                ),
                "parsed: {:?}",
                cli.command
            );
            Ok(())
        }

        /// Edge: the hidden command is not in the help.
        #[test]
        fn internal_fetch_is_not_in_the_help() {
            use clap::CommandFactory as _;
            let help = G729Cli::command().render_help().to_string();
            assert!(!help.contains("internal-fetch"), "hidden: {help}");
        }

        /// Failure: the hidden command needs its user.
        #[test]
        fn internal_fetch_needs_its_user() {
            use clap::Parser as _;
            assert!(
                G729Cli::try_parse_from(["sipnab g729", "internal-fetch"]).is_err(),
                "--as-user is required"
            );
        }

        // ---- what the child sends ----

        /// Success: an answer of exactly the limit is read.
        #[test]
        fn an_answer_of_the_limit_is_read() -> Result<(), TestError> {
            let mut answer = std::io::Cursor::new(vec![7u8; 16]);
            assert_eq!(
                read_answer(&mut answer, "nobody", 16)?.len(),
                16,
                "all of it"
            );
            Ok(())
        }

        /// Success: a shorter answer is read whole.
        #[test]
        fn a_short_answer_is_read() -> Result<(), TestError> {
            let mut answer = std::io::Cursor::new(vec![7u8; 3]);
            assert_eq!(
                read_answer(&mut answer, "nobody", 16)?,
                [7, 7, 7],
                "the bytes"
            );
            Ok(())
        }

        /// Failure: one byte past the limit is refused, naming the user.
        #[test]
        fn an_answer_past_the_limit_is_refused() -> Result<(), TestError> {
            let mut answer = std::io::Cursor::new(vec![7u8; 17]);
            let why = read_answer(&mut answer, "nobody", 16)
                .err()
                .ok_or("refused")?;
            assert!(why.contains("'nobody'"), "names the user: {why}");
            assert!(why.contains("16"), "names the limit: {why}");
            Ok(())
        }

        /// Failure: a pipe that breaks is reported.
        #[test]
        fn a_broken_pipe_is_reported() -> Result<(), TestError> {
            let why = read_answer(&mut Broken, "nobody", 16)
                .err()
                .ok_or("refused")?;
            assert!(why.contains("the pipe broke (test)"), "the error: {why}");
            Ok(())
        }

        /// Edge: a child that never stops sending is cut off one byte past
        /// the limit, not read to the end.
        #[test]
        fn an_endless_answer_is_cut_off() -> Result<(), TestError> {
            let why = read_answer(&mut std::io::repeat(7), "nobody", 1024)
                .err()
                .ok_or("refused")?;
            assert!(why.contains("more than 1024 bytes"), "the refusal: {why}");
            Ok(())
        }

        /// Edge: an empty answer is read as empty.
        #[test]
        fn an_empty_answer_is_empty() -> Result<(), TestError> {
            let mut answer = std::io::Cursor::new(Vec::new());
            assert!(read_answer(&mut answer, "nobody", 16)?.is_empty(), "empty");
            Ok(())
        }

        /// Edge: a limit of zero takes no byte.
        #[test]
        fn a_zero_limit_takes_no_byte() {
            let mut answer = std::io::Cursor::new(vec![1u8]);
            assert!(
                read_answer(&mut answer, "nobody", 0).is_err(),
                "one byte is too many"
            );
        }

        /// Edge: the limit a root install reads with is one table file.
        #[test]
        fn the_limit_is_one_table_file() -> Result<(), TestError> {
            let table = test_support::table_file()?;
            assert_eq!(
                table.len(),
                g729::FILE_LEN,
                "a table file is FILE_LEN bytes"
            );
            let mut answer = std::io::Cursor::new(table.to_vec());
            assert_eq!(
                read_answer(&mut answer, "nobody", g729::FILE_LEN)?.len(),
                g729::FILE_LEN,
                "read whole"
            );
            Ok(())
        }

        // ---- the parent's check of the table ----

        /// Success: a child that ended with 0 and sent a table file.
        #[test]
        fn a_child_that_sent_a_table_file_installs_it() -> Result<(), TestError> {
            let table = test_support::table_file()?.to_vec();
            assert_eq!(
                child_table("nobody", Some(0), table.clone())?,
                table,
                "as sent"
            );
            Ok(())
        }

        /// Failure: a child that ended with 1.
        #[test]
        fn a_child_that_failed_is_reported() -> Result<(), TestError> {
            let why = child_table("nobody", Some(1), Vec::new())
                .err()
                .ok_or("refused")?;
            assert!(why.contains("'nobody'"), "names the user: {why}");
            assert!(why.contains("exit 1"), "names the exit: {why}");
            assert!(why.contains("Nothing was installed."), "says so: {why}");
            Ok(())
        }

        /// Failure: a child a signal ended.
        #[test]
        fn a_child_a_signal_ended_is_reported() -> Result<(), TestError> {
            let why = child_table("nobody", None, Vec::new())
                .err()
                .ok_or("refused")?;
            assert!(why.contains("signal"), "says a signal: {why}");
            Ok(())
        }

        /// Failure: a child that ended with 0 and sent bytes that are not a
        /// table file.
        #[test]
        fn a_child_that_sent_garbage_is_refused() -> Result<(), TestError> {
            let why = child_table("nobody", Some(0), b"not a table".to_vec())
                .err()
                .ok_or("refused")?;
            assert!(why.contains("Refused the table file"), "the refusal: {why}");
            assert!(why.contains("Nothing was installed."), "says so: {why}");
            Ok(())
        }

        /// Failure: a child that ended with 0 and sent nothing.
        #[test]
        fn a_child_that_sent_nothing_is_refused() {
            assert!(
                child_table("nobody", Some(0), Vec::new()).is_err(),
                "an empty answer is not a table file"
            );
        }

        /// Failure: one value changed: the values hash refuses it, named.
        #[test]
        fn a_child_that_sent_altered_values_is_refused() -> Result<(), TestError> {
            let mut altered = test_support::table_file()?.to_vec();
            let last = altered.len() - 1;
            altered[last] ^= 1;
            let why = child_table("nobody", Some(0), altered)
                .err()
                .ok_or("refused")?;
            assert!(
                why.contains(g729::tables::VALUES_SHA256),
                "names the expected values hash: {why}"
            );
            Ok(())
        }

        /// Edge: a child refused as root ends with 2, reported as an exit.
        #[test]
        fn a_child_refused_as_root_is_reported() -> Result<(), TestError> {
            let why = child_table("root", Some(2), Vec::new())
                .err()
                .ok_or("refused")?;
            assert!(why.contains("exit 2"), "names the exit: {why}");
            Ok(())
        }

        // ---- an install as root, up to the child ----

        /// Failure: a user that does not exist is refused before any
        /// download.
        #[test]
        fn a_user_that_does_not_exist_is_refused_before_the_download() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let exe = Path::new(NO_SUCH_EXE);
            let ran = run_in(
                &install(Some(NO_SUCH_USER), false),
                &target,
                "",
                &no_network,
                &env(true, Path::new("/tmp"), Some(exe)),
            );
            assert_eq!(ran.code, 1, "refused: {}{}", ran.out, ran.err);
            assert!(
                ran.err.contains(NO_SUCH_USER),
                "names the user: {}",
                ran.err
            );
            assert!(
                !ran.err.contains("a test tried to download"),
                "no download: {}",
                ran.err
            );
            assert!(!target.exists(), "nothing installed");
            Ok(())
        }

        /// Failure: a TMPDIR the drop user cannot write in is refused before
        /// any download, in the drop refusal's words.
        #[test]
        fn a_tmpdir_the_drop_user_cannot_write_is_refused_first() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let work = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let exe = Path::new(NO_SUCH_EXE);
            let ran = run_in(
                &install(Some("nobody"), false),
                &target,
                "",
                &no_network,
                &env(true, work.path(), Some(exe)),
            );
            assert_eq!(ran.code, 1, "refused: {}{}", ran.out, ran.err);
            assert!(
                ran.err
                    .contains("runs as user 'nobody', and 'nobody' cannot write in"),
                "the drop refusal: {}",
                ran.err
            );
            assert!(
                !ran.err.contains("a test tried to download"),
                "no download: {}",
                ran.err
            );
            assert_eq!(entries(work.path())?, 0, "nothing made in TMPDIR");
            Ok(())
        }

        /// Failure: no binary to run the child with.
        #[test]
        fn no_binary_for_the_child_is_refused() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let ran = run_in(
                &install(Some("nobody"), false),
                &target,
                "",
                &no_network,
                &env(true, Path::new("/tmp"), None),
            );
            assert_eq!(ran.code, 1, "refused: {}{}", ran.out, ran.err);
            assert!(
                ran.err.contains("sipnab binary"),
                "says what is missing: {}",
                ran.err
            );
            assert!(
                ran.err.contains("--no-priv-drop"),
                "the way out: {}",
                ran.err
            );
            assert!(
                !ran.err.contains("a test tried to download"),
                "no download: {}",
                ran.err
            );
            Ok(())
        }

        /// Failure: a child that cannot start is refused, naming the binary
        /// and the user.
        #[test]
        fn a_child_that_cannot_start_is_refused() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let ran = run_in(
                &install(Some("nobody"), false),
                &target,
                "",
                &no_network,
                &env(true, Path::new("/tmp"), Some(Path::new(NO_SUCH_EXE))),
            );
            assert_eq!(ran.code, 1, "refused: {}{}", ran.out, ran.err);
            assert!(
                ran.err
                    .contains("cannot start the download as user 'nobody'"),
                "the refusal: {}",
                ran.err
            );
            assert!(
                ran.err.contains(NO_SUCH_EXE),
                "names the binary: {}",
                ran.err
            );
            assert!(!target.exists(), "nothing installed");
            Ok(())
        }

        /// Success: the install says which user downloads, before it starts
        /// the child.
        #[test]
        fn the_install_names_the_user_that_downloads() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let ran = run_in(
                &install(None, false),
                &target,
                "",
                &no_network,
                &env(true, Path::new("/tmp"), Some(Path::new(NO_SUCH_EXE))),
            );
            assert!(
                ran.out
                    .contains(&format!("Downloading {PACKAGE_URL} as user 'nobody'")),
                "the progress line: {}",
                ran.out
            );
            Ok(())
        }

        /// Success: `--no-priv-drop` downloads in this process and says root
        /// was kept.
        #[test]
        fn no_priv_drop_downloads_here_with_a_warning() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let work = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let ran = run_in(
                &install(None, true),
                &target,
                "",
                &not_the_package,
                &env(true, work.path(), Some(Path::new(NO_SUCH_EXE))),
            );
            assert_eq!(
                ran.code, 1,
                "the package is refused: {}{}",
                ran.out, ran.err
            );
            assert!(
                ran.err
                    .contains("running as root because --no-priv-drop was given"),
                "the warning: {}",
                ran.err
            );
            assert!(
                ran.err.contains(PACKAGE_SHA256),
                "fetched here: {}",
                ran.err
            );
            assert_eq!(entries(work.path())?, 0, "the work directory is gone");
            Ok(())
        }

        /// Success: `[privilege] no_priv_drop = true` keeps root the same way.
        #[test]
        fn config_no_priv_drop_downloads_here_with_a_warning() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let work = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let mut env = env(true, work.path(), Some(Path::new(NO_SUCH_EXE)));
            env.config_no_priv_drop = true;
            let ran = run_in(&install(None, false), &target, "", &not_the_package, &env);
            assert!(
                ran.err
                    .contains("running as root because --no-priv-drop was given"),
                "the warning: {}",
                ran.err
            );
            assert!(
                ran.err.contains(PACKAGE_SHA256),
                "fetched here: {}",
                ran.err
            );
            Ok(())
        }

        /// Success: the config user names the child's user.
        #[test]
        fn the_config_user_names_the_child() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let mut env = env(true, Path::new("/tmp"), Some(Path::new(NO_SUCH_EXE)));
            env.config_user = Some(NO_SUCH_USER);
            let ran = run_in(&install(None, false), &target, "", &no_network, &env);
            assert!(
                ran.err.contains(NO_SUCH_USER),
                "the config user: {}",
                ran.err
            );
            Ok(())
        }

        /// Success: not root, the download runs here in a work directory
        /// under TMPDIR, which is gone afterwards.
        #[test]
        fn not_root_downloads_here_in_tmpdir() -> Result<(), TestError> {
            let dir = tempfile::tempdir()?;
            let work = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let ran = run_in(
                &install(None, false),
                &target,
                "",
                &not_the_package,
                &env(false, work.path(), None),
            );
            assert_eq!(
                ran.code, 1,
                "the package is refused: {}{}",
                ran.out, ran.err
            );
            assert!(
                !ran.err.contains("--no-priv-drop"),
                "no warning: {}",
                ran.err
            );
            assert_eq!(entries(work.path())?, 0, "the work directory is gone");
            assert_eq!(entries(dir.path())?, 0, "nothing beside the target");
            Ok(())
        }

        /// Edge: `--from` as root starts no child and opens no connection.
        #[test]
        fn from_as_root_starts_no_child() -> Result<(), TestError> {
            let package = test_support::package_dir()?;
            let dir = tempfile::tempdir()?;
            let target = dir.path().join(TABLE_FILE_NAME);
            let command = G729Command::Install {
                yes: true,
                from: Some(package),
                user: Some(NO_SUCH_USER.to_string()),
                no_priv_drop: false,
            };
            let ran = run_in(
                &command,
                &target,
                "",
                &no_network,
                &env(true, Path::new("/tmp"), Some(Path::new(NO_SUCH_EXE))),
            );
            assert_eq!(ran.code, 0, "installed: {}{}", ran.out, ran.err);
            assert!(target.exists(), "the table file");
            Ok(())
        }

        // ---- the child ----

        /// Failure: the child refuses to start as root, before any download.
        #[test]
        fn the_child_refuses_root() -> Result<(), TestError> {
            let work = tempfile::tempdir()?;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = internal_fetch("nobody", true, work.path(), &no_network, &mut out, &mut err);
            let err = String::from_utf8_lossy(&err);
            assert_eq!(code, 2, "refused: {err}");
            assert!(err.contains("started as root"), "says why: {err}");
            assert!(
                !err.contains("a test tried to download"),
                "no download: {err}"
            );
            assert!(out.is_empty(), "nothing sent");
            Ok(())
        }

        /// Failure: the child cannot write in TMPDIR: the drop refusal.
        #[test]
        fn the_child_refuses_an_unwritable_tmpdir() -> Result<(), TestError> {
            if !crate::test_prereq::not_root(crate::privilege::is_root()) {
                return Ok(());
            }
            let work = read_only_dir()?;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = internal_fetch("svc", false, work.path(), &no_network, &mut out, &mut err);
            writable_again(&work)?;
            let err = String::from_utf8_lossy(&err);
            assert_eq!(code, 1, "refused: {err}");
            assert!(err.contains("runs as user 'svc'"), "names the user: {err}");
            assert!(
                !err.contains("a test tried to download"),
                "no download: {err}"
            );
            assert!(out.is_empty(), "nothing sent");
            Ok(())
        }

        /// Failure: the download fails: its reason, nothing sent.
        #[test]
        fn the_child_reports_a_failed_download() -> Result<(), TestError> {
            let work = tempfile::tempdir()?;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = internal_fetch("svc", false, work.path(), &unreachable, &mut out, &mut err);
            let err = String::from_utf8_lossy(&err);
            assert_eq!(code, 1, "failed: {err}");
            assert!(err.contains("no route (test)"), "the reason: {err}");
            assert!(out.is_empty(), "nothing sent");
            assert_eq!(entries(work.path())?, 0, "the work directory is gone");
            Ok(())
        }

        /// Failure: a package with another hash: refused, nothing sent, no
        /// file left.
        #[test]
        fn the_child_refuses_another_package() -> Result<(), TestError> {
            let work = tempfile::tempdir()?;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = internal_fetch(
                "svc",
                false,
                work.path(),
                &not_the_package,
                &mut out,
                &mut err,
            );
            let err = String::from_utf8_lossy(&err);
            assert_eq!(code, 1, "refused: {err}");
            assert!(err.contains(PACKAGE_SHA256), "names the pinned hash: {err}");
            assert!(out.is_empty(), "nothing sent");
            assert_eq!(entries(work.path())?, 0, "nothing left in TMPDIR");
            Ok(())
        }

        /// Success: the child says what it read on standard error, so its
        /// standard output carries only the table file.
        #[test]
        fn the_child_reports_what_it_read_on_stderr() -> Result<(), TestError> {
            let work = tempfile::tempdir()?;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let _ = internal_fetch(
                "svc",
                false,
                work.path(),
                &not_the_package,
                &mut out,
                &mut err,
            );
            let err = String::from_utf8_lossy(&err);
            assert!(
                err.contains(&format!("Read {PACKAGE_URL}")),
                "the read line: {err}"
            );
            assert!(out.is_empty(), "stdout is for the table file only");
            Ok(())
        }

        // ---- the early-exit rows ----

        /// Success: the install row says the download drops in a child.
        #[test]
        fn the_install_row_drops_in_a_child() {
            let row = crate::early_exit::early_exit("g729 install");
            assert!(
                row.is_some_and(|row| row.plan == crate::early_exit::Plan::OwnDrop
                    && row.reason.contains("child")
                    && row.reason.contains("--no-priv-drop")),
                "the row: {row:?}"
            );
        }

        /// Success: the child's row says it refuses root.
        #[test]
        fn the_child_has_a_row_that_refuses_root() {
            let row = crate::early_exit::early_exit("g729 internal-fetch");
            assert!(
                row.is_some_and(|row| row.reason.contains("refuses to start as root")),
                "the row: {row:?}"
            );
        }
    }
}
