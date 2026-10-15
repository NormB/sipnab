// SPDX-License-Identifier: MIT OR Apache-2.0
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
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { 2 } else { 0 };
        }
    };
    let key = match crate::config::Config::load(cli.config.as_deref(), cli.no_config) {
        Ok(loaded) => loaded.config.g729.tables,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{e}");
            return 1;
        }
    };
    let location = TableLocation {
        flag: cli.g729_tables.clone(),
        key,
        default: crate::rtp::g729_tables::default_table_file_here(),
    };
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let mut io = Io {
        input: &mut input,
        out: &mut out,
        err: &mut err,
    };
    run(&cli.command, &location, &mut io, &download)
}

/// Run one `sipnab g729` command against `location`. Exit codes: 0 done (or
/// installed, for `status`), 1 refused or failed (or not installed).
pub fn run(
    command: &G729Command,
    location: &TableLocation,
    io: &mut Io<'_>,
    fetch: Fetch<'_>,
) -> i32 {
    let outcome = match command {
        G729Command::Status => return status(location, io.out),
        G729Command::Install { yes, from } => install(location, *yes, from.as_deref(), io, fetch),
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
        None => {
            let _ = writeln!(io.out, "Downloading {PACKAGE_URL} ...");
            let package = fetch(PACKAGE_URL)?;
            let _ = writeln!(
                io.out,
                "Read {PACKAGE_URL} ({} bytes, sha256 {})",
                package.len(),
                sha256(&package)
            );
            table_file_from_download(package, target)?
        }
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
    install(location, true, None, &mut io, fetch)?.ok_or_else(|| "Not installed.".to_string())
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
/// first, the bytes go to a temporary file beside `target` for the importer,
/// and that file is deleted whatever happens.
///
/// # Errors
///
/// A package whose sha256 is not the pinned one, a temporary file that cannot
/// be written, or the importer's refusal.
pub fn table_file_from_download(package: Vec<u8>, target: &Path) -> Result<Vec<u8>, String> {
    let actual = sha256(&package);
    if actual != PACKAGE_SHA256 {
        return package_refusal(&format!("the download from {PACKAGE_URL}"), &actual);
    }
    let dir = target_dir(target);
    create_dir(&dir)?;
    let written = tempfile::Builder::new()
        .prefix(".sipnab-g729-package-")
        .suffix(".zip")
        .tempfile_in(&dir)
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
    let endpoint = Endpoint::parse(url).map_err(|e| format!("{url}: {e}"))?;
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
            let (body, more) = read_body(reader, &head, PACKAGE_BYTES);
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
}
