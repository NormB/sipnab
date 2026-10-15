// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--vcon-resign`: re-sign a signed vCon for a long-term archive.
//!
//! [draft-ietf-vcon-vcon-core-04 section 5.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2.3)
//! keeps a signed vCon's integrity past its signing certificate's lifetime:
//! "Before the expiration of the JWS1 signing certificate, the content of
//! JWS1 (the vCon) is verified and then JWS1 is signed as the payload to
//! construct JWS2." The step is [`crate::output::vcon_jose::resign_at`];
//! this reads the files, writes the result, and names the exit code.

use std::path::{Path, PathBuf};

/// Exit code of a refused input or an output that exists.
const REFUSED: i32 = 1;

/// Exit code of settings that cannot be used: a key, a certificate or the
/// signer CA that does not read.
const BAD_SETTINGS: i32 = 2;

/// Re-sign the file `--vcon-resign` names and write `--vcon-resign-out`.
///
/// # Errors
///
/// The exit code and the reason: 2 for a key, certificate or signer check
/// that does not load; 1 for an input that does not read or is refused
/// ([`crate::output::vcon_jose::resign_at`]), and for an output that exists
/// or cannot be written.
pub fn run(args: &crate::cli::VconResignArgs) -> Result<PathBuf, (i32, String)> {
    let missing = |flag: &str| (BAD_SETTINGS, format!("needs {flag}"));
    let input = args.vcon_resign.as_ref().ok_or_else(|| missing("a file"))?;
    let key = args
        .vcon_resign_key
        .as_ref()
        .ok_or_else(|| missing("--vcon-resign-key"))?;
    let cert = args
        .vcon_resign_cert
        .as_ref()
        .ok_or_else(|| missing("--vcon-resign-cert"))?;
    let out = args
        .vcon_resign_out
        .as_ref()
        .ok_or_else(|| missing("--vcon-resign-out"))?;
    let signer = crate::output::vcon_jose::load_signing(key, cert)
        .map_err(|e| (BAD_SETTINGS, format!("--vcon-resign-key: {e}")))?
        .signer;
    let opener = crate::capture::vcon_input::opener().map_err(|e| (BAD_SETTINGS, e))?;
    let cap = crate::capture::vcon_input::MAX_CONTAINER_BYTES;
    let bytes = read_capped(input, cap).map_err(|e| (REFUSED, e))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let resigned = crate::output::vcon_jose::resign_at(
        &bytes,
        &signer,
        &opener,
        usize::try_from(cap).unwrap_or(usize::MAX),
        now,
    )
    .map_err(|e| (REFUSED, format!("'{}': {e}", input.display())))?;
    write_new(out, &resigned).map_err(|e| (REFUSED, e))?;
    Ok(out.clone())
}

/// The file at `path`, refused when it is over `cap` bytes.
pub(crate) fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let len = std::fs::metadata(path)
        .map_err(|e| format!("cannot read '{}': {e}", path.display()))?
        .len();
    if len > cap {
        return Err(format!(
            "'{}' is {len} bytes, over the {cap}-byte limit for one container",
            path.display()
        ));
    }
    std::fs::read(path).map_err(|e| format!("cannot read '{}': {e}", path.display()))
}

/// Write `bytes` to a new file at `path`, mode 0600, never replacing one
/// that exists or following a link.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "'{}' exists; sipnab never replaces it: name a new file",
                path.display()
            )
        } else {
            format!("cannot create '{}': {e}", path.display())
        }
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write '{}': {e}", path.display()))
}
