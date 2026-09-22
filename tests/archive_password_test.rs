// SPDX-License-Identifier: MIT OR Apache-2.0

//! Password-protected capture archives, through the real binary.
//!
//! Every fixture is built here, at test time: the captures by
//! `support/pcap_build.rs`, the encrypted ZIPs by the `zip` crate, and every
//! password minted at runtime from the clock and the process id. No encrypted
//! blob and no password is committed.
//!
//! Each run's password is also a SENTINEL: every run here is made at
//! `SIPNAB_LOG=trace`, and no byte of its stdout or stderr may contain the
//! password (Invariant 5).
#![cfg(all(feature = "native", feature = "archive"))]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "support/pcap_build.rs"]
mod pcap_build;

/// A password nobody wrote down: this process, this instant, and a label.
fn mint(label: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut h);
    std::process::id().hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        .hash(&mut h);
    format!("pw {:016x} {label} ", h.finish())
}

/// A capture holding one SIP call, `call_id`.
fn capture(call_id: &str) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tmp");
    let p = dir.path().join("c.pcap");
    let frames: Vec<(Vec<u8>, u64)> = pcap_build::sip_call_frames(call_id, "b1", "alice", "bob")
        .into_iter()
        .enumerate()
        .map(|(i, f)| (f, 10_000_000 + i as u64 * 1_000))
        .collect();
    pcap_build::write_pcap_at(&p, &frames, 1);
    std::fs::read(&p).expect("read back")
}

/// How a fixture member is locked.
#[derive(Clone, Copy)]
enum Lock<'a> {
    None,
    ZipCrypto(&'a str),
    Aes(&'a str),
}

/// A ZIP of `(name, bytes, lock)` members.
fn zip_of(entries: &[(&str, &[u8], Lock<'_>)]) -> Vec<u8> {
    use zip::unstable::write::FileOptionsExt;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data, lock) in entries {
        let base = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let opts = match lock {
            Lock::None => base,
            Lock::ZipCrypto(pw) => base
                .with_deprecated_encryption(pw.as_bytes())
                .expect("zipcrypto"),
            Lock::Aes(pw) => base.with_aes_encryption(zip::AesMode::Aes256, pw),
        };
        w.start_file(*name, opts).expect("start");
        w.write_all(data).expect("write");
    }
    w.finish().expect("finish").into_inner()
}

/// A file only its owner can read, as a password file must be.
fn private_file(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

/// What a run produced.
struct Run {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

/// Run the binary over `args` at trace level, with `env` set and `stdin` fed.
fn run(args: &[&str], env: &[(&str, &str)], stdin: Option<&str>, tmpdir: &Path) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.args(args)
        .env("TMPDIR", tmpdir)
        .env("SIPNAB_LOG", "trace")
        .env("NO_COLOR", "1")
        .env_remove("SIPNAB_ARCHIVE_PASSWORD")
        .env_remove("CREDENTIALS_DIRECTORY")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn sipnab");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("feed stdin");
    }
    let out = child.wait_with_output().expect("wait");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code(),
    }
}

/// The arguments that print a run's dialogs as JSON.
fn read_args(spec: &str) -> Vec<String> {
    [
        "-N",
        "-I",
        spec,
        "--json-dialogs",
        "--no-cli-print",
        "--portrange",
        "1-65535",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// Invariant 5, for one run: the password appears in no byte of its output.
fn assert_sealed(r: &Run, password: &str) {
    for (what, text) in [("stdout", &r.stdout), ("stderr", &r.stderr)] {
        assert!(!text.contains(password), "the password appeared in {what}");
        // Its distinctive core, too, in case something trimmed or split it.
        let core = password.trim();
        assert!(
            !text.contains(core),
            "the password's core appeared in {what}"
        );
    }
}

/// An AES-256 ZIP of one call, locked with `password`, in `dir`.
fn locked_zip(dir: &Path, name: &str, call_id: &str, password: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(
        &path,
        zip_of(&[("calls/a.pcap", &capture(call_id), Lock::Aes(password))]),
    )
    .expect("write zip");
    path
}

#[test]
fn every_source_opens_a_locked_archive() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("sources");
    let zip = locked_zip(root.path(), "evidence.zip", "src-call@test", &password);
    let spec = zip.display().to_string();

    let file = root.path().join("pw.txt");
    private_file(&file, &format!("{password}\n"));
    let creds = root.path().join("creds");
    std::fs::create_dir(&creds).expect("mkdir");
    private_file(&creds.join("archive-password"), &format!("{password}\n"));
    let file_s = file.display().to_string();
    let command = format!("cat {}", file.display());
    let creds_s = creds.display().to_string();

    type Case<'a> = (
        &'a str,
        Vec<String>,
        Vec<(&'a str, &'a str)>,
        Option<String>,
    );
    let cases: Vec<Case<'_>> = vec![
        (
            "file",
            vec!["--archive-password-file".into(), file_s.clone()],
            vec![],
            None,
        ),
        (
            "command",
            vec!["--archive-password-command".into(), command.clone()],
            vec![],
            None,
        ),
        (
            "stdin",
            vec!["--archive-password-stdin".into()],
            vec![],
            Some(format!("{password}\n")),
        ),
        (
            "systemd credential",
            vec![],
            vec![("CREDENTIALS_DIRECTORY", creds_s.as_str())],
            None,
        ),
        (
            "environment",
            vec![],
            vec![("SIPNAB_ARCHIVE_PASSWORD", password.as_str())],
            None,
        ),
        (
            "inline",
            vec!["--archive-password".into(), password.clone()],
            vec![],
            None,
        ),
    ];
    for (what, extra, env, stdin) in cases {
        let mut args = read_args(&spec);
        args.extend(extra);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = run(&argv, &env, stdin.as_deref(), tmp.path());
        assert_eq!(r.code, Some(0), "{what}: exit status\n{}", r.stderr);
        assert!(
            r.stdout.contains("src-call@test"),
            "{what}: the call inside the locked member was read\n{}",
            r.stderr
        );
        let warned = r
            .stderr
            .contains("WARNING! Using --archive-password on the command line");
        assert_eq!(
            warned,
            what == "inline",
            "{what}: the inline warning\n{}",
            r.stderr
        );
        if what != "inline" {
            assert_sealed(&r, &password);
        }
    }
}

#[test]
fn the_inline_flag_warns_and_still_never_echoes_the_password() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("inline");
    let zip = locked_zip(root.path(), "e.zip", "inline@test", &password);
    let mut args = read_args(&zip.display().to_string());
    args.extend(["--archive-password".to_string(), password.clone()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = run(&argv, &[], None, tmp.path());
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr.contains(
            "--archive-password-stdin, --archive-password-file or --archive-password-command"
        ),
        "{}",
        r.stderr
    );
    // The command line is the operator's own; what sipnab PRINTS must still
    // never repeat it.
    assert_sealed(&r, &password);
}

#[cfg(unix)]
#[test]
fn an_own_password_file_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("perm");
    let zip = locked_zip(root.path(), "e.zip", "perm@test", &password);
    let file = root.path().join("pw.txt");
    std::fs::write(&file, format!("{password}\n")).expect("write");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let mut args = read_args(&zip.display().to_string());
    args.extend([
        "--archive-password-file".to_string(),
        file.display().to_string(),
    ]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = run(&argv, &[], None, tmp.path());
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(
        r.stderr.contains("mode 0644") && r.stderr.contains("chmod 600"),
        "{}",
        r.stderr
    );
    assert_sealed(&r, &password);
}

#[test]
fn a_named_archive_with_nothing_readable_fails_and_names_why() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("named");
    let zip = locked_zip(root.path(), "e.zip", "named@test", &password);
    let spec = zip.display().to_string();

    let r = run(
        &read_args(&spec)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        &[],
        None,
        tmp.path(),
    );
    assert_eq!(r.code, Some(1), "no password: exit status\n{}", r.stderr);
    assert!(
        r.stderr.contains(&format!("{spec}/calls/a.pcap"))
            && r.stderr.contains("encrypted_no_password"),
        "{}",
        r.stderr
    );

    let wrong = mint("named-wrong");
    let mut args = read_args(&spec);
    args.extend(["--archive-password".to_string(), wrong.clone()]);
    let r = run(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &[],
        None,
        tmp.path(),
    );
    assert_eq!(r.code, Some(1), "wrong password: exit status\n{}", r.stderr);
    assert!(
        r.stderr.contains("encrypted_wrong_password"),
        "{}",
        r.stderr
    );
    assert_sealed(&r, &wrong);
    assert_sealed(&r, &password);
}

#[test]
fn some_members_read_is_a_success_with_the_rest_tallied() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("partial");
    let path = root.path().join("mixed.zip");
    std::fs::write(
        &path,
        zip_of(&[
            ("open.pcap", &capture("open@test"), Lock::None),
            ("locked.pcap", &capture("locked@test"), Lock::Aes(&password)),
        ]),
    )
    .expect("write");
    let spec = path.display().to_string();
    let r = run(
        &read_args(&spec)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        &[],
        None,
        tmp.path(),
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stdout.contains("open@test"));
    assert!(!r.stdout.contains("locked@test"));
    assert!(
        r.stderr
            .contains(&format!("Skipping '{spec}/locked.pcap': encrypted")),
        "{}",
        r.stderr
    );
    assert!(
        r.stderr.contains("1 archive member(s) not read"),
        "{}",
        r.stderr
    );
}

#[test]
fn the_zipcrypto_warning_prints_once_per_archive() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("zipcrypto");
    let path = root.path().join("legacy.zip");
    std::fs::write(
        &path,
        zip_of(&[
            ("a.pcap", &capture("zc-a@test"), Lock::ZipCrypto(&password)),
            ("b.pcap", &capture("zc-b@test"), Lock::ZipCrypto(&password)),
        ]),
    )
    .expect("write");
    let mut args = read_args(&path.display().to_string());
    let file = root.path().join("pw");
    private_file(&file, &format!("{password}\n"));
    args.extend([
        "--archive-password-file".to_string(),
        file.display().to_string(),
    ]);
    let r = run(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &[],
        None,
        tmp.path(),
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stdout.contains("zc-a@test") && r.stdout.contains("zc-b@test"));
    assert_eq!(
        r.stderr
            .matches("uses ZipCrypto, which does not protect")
            .count(),
        1,
        "{}",
        r.stderr
    );
    assert_sealed(&r, &password);
}

#[test]
fn allowing_a_core_dump_while_holding_a_password_warns() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmp");
    let password = mint("core");
    let zip = locked_zip(root.path(), "e.zip", "core@test", &password);
    let file = root.path().join("pw");
    private_file(&file, &format!("{password}\n"));
    let mut args = read_args(&zip.display().to_string());
    args.extend([
        "--archive-password-file".to_string(),
        file.display().to_string(),
        "--allow-coredump".to_string(),
    ]);
    let r = run(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &[],
        None,
        tmp.path(),
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr
            .contains("a core dump would contain the archive password"),
        "{}",
        r.stderr
    );
    assert_sealed(&r, &password);
}

#[test]
fn an_unknown_password_encoding_is_refused() {
    let tmp = tempfile::tempdir().expect("tmp");
    let r = run(
        &["-N", "-I", "x.zip", "--archive-password-encoding", "ebcdic"],
        &[],
        None,
        tmp.path(),
    );
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(r.stderr.contains("cp437"), "{}", r.stderr);
}
