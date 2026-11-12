// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `[hep] listen` and `[hep] allow`: the HEP listener's address and its
//! allowlist from the config file (HEP-LISTEN-CONFIG-KEYS).
//!
//! `--hep-listen` and `--hep-allow` had no config-file key, so a service that
//! receives HEP had to carry them on its command line. The keys follow the
//! usual precedence: a flag replaces its key.
//!
//! Each test writes a config file and runs the startup pipeline the binary
//! runs (parse, `Cli::validate`, `bootstrap::load_config`, `bootstrap::plan`),
//! then reads the planned capture source. No socket is opened: `plan` decides
//! the source and the listener binds later, in a step these tests do not
//! reach. Addresses are loopback or from RFC 5737.
//!
//! Counts: 20 success, 18 failure, 19 edge.
#![cfg(feature = "full")]

use sipnab::app::bootstrap::{RunPlan, load_config, plan};
use sipnab::capture::CaptureSource;
use sipnab::cli::Cli;
use sipnab::config::Config;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// A saved capture, for the runs that read a file.
const CAPTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ice_checks.pcap"
);

/// Where the pipeline stopped, with the exit code and message of a refusal.
#[derive(Debug)]
struct Refusal {
    stage: &'static str,
    code: i32,
    message: String,
}

/// A run the pipeline accepted.
struct Accepted {
    cli: Cli,
    config: Config,
    plan: RunPlan,
}

/// `sipnab -N <args> -f <file holding toml>` through parse, validate,
/// `load_config` and `plan`.
fn run(args: &[&str], toml: &str) -> Result<Result<Accepted, Refusal>, TestError> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("sipnab.toml");
    std::fs::write(&file, toml)?;
    let mut argv: Vec<String> = vec!["sipnab".into(), "-N".into()];
    argv.extend(args.iter().map(|a| (*a).to_string()));
    argv.push("-f".into());
    argv.push(file.display().to_string());
    let refusal = |stage, code, message| {
        Ok(Err(Refusal {
            stage,
            code,
            message,
        }))
    };
    let cli = match Cli::try_parse_from_args(argv) {
        Ok(cli) => cli,
        Err(e) => return refusal("parse", e.exit_code(), e.to_string()),
    };
    if let Err(e) = cli.validate() {
        return refusal("validate", 2, e.to_string());
    }
    let loaded = match load_config(&cli) {
        Ok(loaded) => loaded,
        Err(e) => return refusal("config", e.exit_code, e.message),
    };
    match plan(&cli, &loaded.config) {
        Ok(plan) => Ok(Ok(Accepted {
            cli,
            config: loaded.config,
            plan,
        })),
        Err(e) => refusal("plan", e.exit_code, e.message),
    }
}

/// The accepted run, or an error that carries the refusal.
fn accepted(args: &[&str], toml: &str) -> Result<Accepted, TestError> {
    run(args, toml)?.map_err(|r| format!("refused, and it must be accepted: {r:?}").into())
}

/// The refusal, or an error when the run was accepted.
fn refused(args: &[&str], toml: &str) -> Result<Refusal, TestError> {
    match run(args, toml)? {
        Ok(_) => Err(format!("accepted, and it must be refused: {args:?} with {toml:?}").into()),
        Err(refusal) => Ok(refusal),
    }
}

/// The HEP listeners in a planned source: (bind address, allowlist length).
fn listeners(source: Option<&CaptureSource>) -> Vec<(String, usize)> {
    match source {
        Some(CaptureSource::Hep {
            bind_addr,
            allowlist,
            ..
        }) => vec![(bind_addr.clone(), allowlist.len())],
        Some(CaptureSource::Composite(members)) => {
            members.iter().flat_map(|m| listeners(Some(m))).collect()
        }
        _ => Vec::new(),
    }
}

/// The one HEP listener a run planned.
fn listener(run: &Accepted) -> Result<(String, usize), TestError> {
    let found = listeners(run.plan.source.as_ref());
    match found.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(format!("the run planned {} HEP listener(s): {found:?}", found.len()).into()),
    }
}

const LOOPBACK: &str = "[hep]\nlisten = \"127.0.0.1:9060\"\n";
const ROUTABLE: &str =
    "[hep]\nlisten = \"192.0.2.10:9060\"\nallow = [\"198.51.100.0/24\", \"203.0.113.7\"]\n";

// ---------------------------------------------------------------------------
// Success: the keys start and configure the listener.
// ---------------------------------------------------------------------------

/// The defect: a run with no HEP flag and `[hep] listen` in the file planned
/// no listener. Now the key is the listener's address.
#[test]
fn success_the_key_alone_starts_the_listener() -> Result<(), TestError> {
    let run = accepted(&[], LOOPBACK)?;
    assert_eq!(
        listener(&run)?.0,
        "127.0.0.1:9060",
        "the listener binds the address the key names"
    );
    Ok(())
}

#[test]
fn success_the_accessor_returns_the_key() -> Result<(), TestError> {
    let run = accepted(&[], LOOPBACK)?;
    assert_eq!(
        run.cli.hep_listen(&run.config),
        Some("127.0.0.1:9060"),
        "with no flag the key is the address"
    );
    Ok(())
}

#[test]
fn success_the_flag_replaces_the_key() -> Result<(), TestError> {
    let run = accepted(&["--hep-listen", "127.0.0.1:9070"], LOOPBACK)?;
    assert_eq!(
        listener(&run)?.0,
        "127.0.0.1:9070",
        "the flag's address wins over the key's"
    );
    Ok(())
}

#[test]
fn success_the_short_flag_replaces_the_key() -> Result<(), TestError> {
    let run = accepted(&["-L", "127.0.0.1:9071"], LOOPBACK)?;
    assert_eq!(listener(&run)?.0, "127.0.0.1:9071", "-L is --hep-listen");
    Ok(())
}

#[test]
fn success_the_flag_alone_still_starts_the_listener() -> Result<(), TestError> {
    let run = accepted(&["--hep-listen", "127.0.0.1:9072"], "")?;
    assert_eq!(
        listener(&run)?,
        ("127.0.0.1:9072".to_string(), 0),
        "a file without the keys changes nothing for the flags"
    );
    Ok(())
}

#[test]
fn success_the_allow_key_is_the_listeners_allowlist() -> Result<(), TestError> {
    let run = accepted(&[], ROUTABLE)?;
    assert_eq!(
        listener(&run)?,
        ("192.0.2.10:9060".to_string(), 2),
        "both entries of [hep] allow are admitted sources"
    );
    Ok(())
}

/// A routable bind needs a secret or an allowlist. The key's allowlist
/// satisfies that as the flag's does.
#[test]
fn success_the_allow_key_satisfies_the_bind_policy() -> Result<(), TestError> {
    let run = accepted(&[], ROUTABLE)?;
    assert_eq!(
        run.cli.hep_allow(&run.config),
        ["198.51.100.0/24", "203.0.113.7"],
        "the accessor returns the key's entries in order"
    );
    Ok(())
}

#[test]
fn success_the_allow_flag_replaces_the_allow_key() -> Result<(), TestError> {
    let run = accepted(&["--hep-allow", "198.51.100.9"], ROUTABLE)?;
    assert_eq!(
        run.cli.hep_allow(&run.config),
        ["198.51.100.9"],
        "the flag's list replaces the key's, it is not added to it"
    );
    assert_eq!(listener(&run)?.1, 1, "one admitted source, from the flag");
    Ok(())
}

#[test]
fn success_the_allow_flag_given_twice_replaces_the_key_with_both() -> Result<(), TestError> {
    let run = accepted(
        &[
            "--hep-allow",
            "198.51.100.9",
            "--hep-allow",
            "198.51.100.10",
        ],
        ROUTABLE,
    )?;
    assert_eq!(listener(&run)?.1, 2, "two flag values, none from the key");
    Ok(())
}

#[test]
fn success_the_listen_flag_uses_the_allow_key() -> Result<(), TestError> {
    let run = accepted(
        &["--hep-listen", "192.0.2.20:9060"],
        "[hep]\nallow = [\"198.51.100.0/24\"]\n",
    )?;
    assert_eq!(
        listener(&run)?,
        ("192.0.2.20:9060".to_string(), 1),
        "the address from the flag, the allowlist from the file"
    );
    Ok(())
}

#[test]
fn success_the_listen_key_uses_the_allow_flag() -> Result<(), TestError> {
    let run = accepted(
        &["--hep-allow", "198.51.100.0/24"],
        "[hep]\nlisten = \"192.0.2.10:9060\"\n",
    )?;
    assert_eq!(
        listener(&run)?,
        ("192.0.2.10:9060".to_string(), 1),
        "--hep-allow is accepted with the listener from the file"
    );
    Ok(())
}

/// Each listener-only flag was refused by the parser without `--hep-listen`
/// on the command line. A listener from the file satisfies it.
#[test]
fn success_listener_only_flags_are_accepted_with_the_key() -> Result<(), TestError> {
    for flags in [
        &["--hep-senders"][..],
        &["--th-mappings"],
        &["--hep-rate-limit", "1000"],
        &["--hep-rate-limit-per-peer", "auto"],
        &["--hep-listen-transport", "tcp"],
        &["--hep-hmac-window", "60"],
        &["--hep-silence-warn", "30"],
    ] {
        let run = accepted(flags, LOOPBACK)?;
        assert_eq!(
            listener(&run)?.0,
            "127.0.0.1:9060",
            "{flags:?} runs with the listener from the file"
        );
    }
    Ok(())
}

#[test]
fn success_the_auth_mode_flag_is_accepted_with_the_key() -> Result<(), TestError> {
    let run = accepted(&["--hep-auth-mode", "hmac"], LOOPBACK)?;
    assert_eq!(
        listener(&run)?.0,
        "127.0.0.1:9060",
        "a flag either HEP side reads is accepted with the listener from the file"
    );
    Ok(())
}

/// `-d eth0 -L addr` is one interface plus one listener. The key composes
/// with a device the same way.
#[test]
fn success_the_key_composes_with_a_device() -> Result<(), TestError> {
    let run = accepted(&["-d", "lo"], LOOPBACK)?;
    assert!(
        matches!(run.plan.source, Some(CaptureSource::Composite(_))),
        "a device and the key plan a composite source: {:?}",
        run.plan.source.as_ref().map(CaptureSource::label)
    );
    assert_eq!(listener(&run)?.0, "127.0.0.1:9060", "the HEP member");
    Ok(())
}

#[test]
fn success_the_listener_keys_read_as_applied_not_inert() -> Result<(), TestError> {
    let run = accepted(
        &[],
        "[hep]\nlisten = \"127.0.0.1:9060\"\n[limits]\nhep_rate_limit = 500\n",
    )?;
    let warnings = run.cli.inert_key_warnings(&run.config);
    assert!(
        warnings.is_empty(),
        "[limits] hep_rate_limit applies to the listener the file starts: {warnings:?}"
    );
    Ok(())
}

/// A flag both HEP sides read is satisfied by the sender alone.
#[test]
fn success_a_sender_satisfies_a_flag_both_sides_read() -> Result<(), TestError> {
    let cli = Cli::try_parse_from_args([
        "sipnab",
        "-N",
        "--hep-send",
        "192.0.2.50:9060",
        "--hep-auth-mode",
        "hmac",
    ])?;
    assert_eq!(
        cli.hep_side_flags_problem(&Config::default()),
        None,
        "--hep-auth-mode applies to the sender this run starts"
    );
    Ok(())
}

#[test]
fn success_dump_config_writes_the_keys_back() -> Result<(), TestError> {
    let run = accepted(&[], ROUTABLE)?;
    let dumped = run.config.dump()?;
    assert!(
        dumped.contains("listen = \"192.0.2.10:9060\""),
        "the dump holds [hep] listen: {dumped}"
    );
    assert!(
        dumped.contains("198.51.100.0/24") && dumped.contains("203.0.113.7"),
        "the dump holds [hep] allow: {dumped}"
    );
    Ok(())
}

#[test]
fn success_the_keys_are_known_keys() -> Result<(), TestError> {
    let unknown = Config::unknown_keys(ROUTABLE)?;
    assert!(
        unknown.is_empty(),
        "[hep] listen and allow are registered, so no unknown-key warning: {unknown:?}"
    );
    Ok(())
}

#[test]
fn success_the_settings_table_pairs_each_flag_with_its_key() {
    use sipnab::settings::{FLAGS, Link, Merge};
    for (flag, key) in [("hep-listen", "listen"), ("hep-allow", "allow")] {
        let link = FLAGS
            .iter()
            .find(|(name, _)| *name == flag)
            .map(|(_, l)| *l);
        assert_eq!(
            link,
            Some(Link::Key("hep", key, Merge::Override)),
            "--{flag} and [hep] {key} set one thing, and the flag replaces the key"
        );
    }
}

#[test]
fn success_an_ipv6_loopback_address_in_the_key_is_planned() -> Result<(), TestError> {
    let run = accepted(&[], "[hep]\nlisten = \"[::1]:9060\"\n")?;
    assert_eq!(
        listener(&run)?.0,
        "[::1]:9060",
        "an IPv6 literal with a port"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Failure: a wrong value is refused before anything runs, by name, with the
// exit code of where it came from (1 for the file, 2 for the command line).
// ---------------------------------------------------------------------------

#[test]
fn failure_an_empty_listen_key_is_refused_by_name() -> Result<(), TestError> {
    let r = refused(&[], "[hep]\nlisten = \"\"\n")?;
    assert_eq!((r.stage, r.code), ("config", 1), "{r:?}");
    assert!(r.message.contains("[hep] listen"), "names the key: {r:?}");
    Ok(())
}

#[test]
fn failure_a_blank_listen_key_is_refused_by_name() -> Result<(), TestError> {
    let r = refused(&[], "[hep]\nlisten = \"  \"\n")?;
    assert_eq!((r.stage, r.code), ("config", 1), "{r:?}");
    assert!(r.message.contains("[hep] listen"), "names the key: {r:?}");
    Ok(())
}

#[test]
fn failure_a_listen_key_that_is_not_an_address_exits_1() -> Result<(), TestError> {
    let r = refused(&[], "[hep]\nlisten = \"not an address\"\n")?;
    assert_eq!(
        r.code, 1,
        "a value from the file is a refused configuration: {r:?}"
    );
    assert!(r.message.contains("[hep] listen"), "names the key: {r:?}");
    Ok(())
}

/// The same value on the command line stays invalid usage, exit 2.
#[test]
fn failure_a_listen_flag_that_is_not_an_address_still_exits_2() -> Result<(), TestError> {
    let r = refused(&["--hep-listen", "not an address"], "")?;
    assert_eq!(r.code, 2, "a value from the command line: {r:?}");
    assert!(r.message.contains("--hep-listen"), "names the flag: {r:?}");
    Ok(())
}

#[test]
fn failure_a_routable_listen_key_without_allow_or_secret_is_refused() -> Result<(), TestError> {
    let r = refused(&[], "[hep]\nlisten = \"192.0.2.10:9060\"\n")?;
    assert_eq!(r.code, 1, "the address came from the file: {r:?}");
    assert!(
        r.message.contains("[hep] allow") && r.message.contains("--hep-allow"),
        "the refusal names both ways to give the allowlist: {r:?}"
    );
    Ok(())
}

#[test]
fn failure_a_routable_listen_flag_without_allow_or_secret_exits_2() -> Result<(), TestError> {
    let r = refused(&["--hep-listen", "192.0.2.10:9060"], "")?;
    assert_eq!(r.code, 2, "the address came from the command line: {r:?}");
    Ok(())
}

#[test]
fn failure_a_malformed_allow_key_entry_is_refused_by_name() -> Result<(), TestError> {
    let r = refused(
        &[],
        "[hep]\nlisten = \"127.0.0.1:9060\"\nallow = [\"198.51.100.0/99\"]\n",
    )?;
    assert_eq!(r.code, 1, "the entry came from the file: {r:?}");
    assert!(
        r.message.contains("[hep] allow") && r.message.contains("198.51.100.0/99"),
        "names the key and the entry: {r:?}"
    );
    Ok(())
}

#[test]
fn failure_a_malformed_allow_flag_still_exits_2() -> Result<(), TestError> {
    let r = refused(&["--hep-allow", "198.51.100.0/99"], LOOPBACK)?;
    assert_eq!(r.code, 2, "the entry came from the command line: {r:?}");
    assert!(r.message.contains("--hep-allow"), "names the flag: {r:?}");
    Ok(())
}

#[test]
fn failure_an_empty_allow_entry_is_refused_by_name() -> Result<(), TestError> {
    let r = refused(&[], "[hep]\nlisten = \"127.0.0.1:9060\"\nallow = [\"\"]\n")?;
    assert_eq!((r.stage, r.code), ("config", 1), "{r:?}");
    assert!(r.message.contains("[hep] allow"), "names the key: {r:?}");
    Ok(())
}

#[test]
fn failure_a_listen_key_of_the_wrong_type_is_refused() -> Result<(), TestError> {
    let r = refused(&[], "[hep]\nlisten = 9060\n")?;
    assert_eq!(
        (r.stage, r.code),
        ("config", 1),
        "a number is not an address: {r:?}"
    );
    Ok(())
}

#[test]
fn failure_an_allow_key_that_is_not_a_list_is_refused() -> Result<(), TestError> {
    let r = refused(
        &[],
        "[hep]\nlisten = \"127.0.0.1:9060\"\nallow = \"198.51.100.7\"\n",
    )?;
    assert_eq!(
        (r.stage, r.code),
        ("config", 1),
        "a string is not a list: {r:?}"
    );
    Ok(())
}

/// The parser used to refuse these. With no listener from either place the
/// refusal stays, with the same exit code, and names both ways to start one.
#[test]
fn failure_listener_only_flags_without_any_listener_are_refused() -> Result<(), TestError> {
    for flags in [
        &["--hep-allow", "198.51.100.7"][..],
        &["--hep-senders"],
        &["--th-mappings"],
        &["--hep-rate-limit", "1000"],
        &["--hep-rate-limit-per-peer", "auto"],
        &["--hep-listen-transport", "tcp"],
        &["--hep-hmac-window", "60"],
        &["--hep-silence-warn", "30"],
    ] {
        let r = refused(flags, "")?;
        assert_eq!(r.code, 2, "{flags:?} is invalid usage: {r:?}");
        assert!(
            r.message.contains(flags[0])
                && r.message.contains("--hep-listen")
                && r.message.contains("[hep] listen"),
            "the refusal names {} and both ways to start the listener: {r:?}",
            flags[0]
        );
    }
    Ok(())
}

#[test]
fn failure_the_auth_mode_flag_without_either_hep_side_is_refused() -> Result<(), TestError> {
    let r = refused(&["--hep-auth-mode", "hmac"], "")?;
    assert_eq!(r.code, 2, "{r:?}");
    assert!(
        r.message.contains("--hep-auth-mode") && r.message.contains("--hep-send"),
        "names the flag and the sender, the other side that reads it: {r:?}"
    );
    Ok(())
}

/// A sender is not a listener: `--hep-send` does not satisfy a listener-only
/// flag.
#[test]
fn failure_a_sender_does_not_satisfy_a_listener_only_flag() -> Result<(), TestError> {
    let r = refused(&["--hep-send", "192.0.2.50:9060", "--hep-senders"], "")?;
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.message.contains("--hep-senders"), "names the flag: {r:?}");
    Ok(())
}

/// `--multi-device` and a HEP listener cannot run together. The key does not
/// get around that, and the refusal says where the listener came from.
#[test]
fn failure_multi_device_with_the_key_is_refused_naming_the_key() -> Result<(), TestError> {
    let r = refused(&["--multi-device", "-d", "lo,lo"], LOOPBACK)?;
    assert!(
        r.message.contains("--multi-device") && r.message.contains("[hep] listen"),
        "names the flag and the key: {r:?}"
    );
    Ok(())
}

#[test]
fn failure_multi_device_with_the_flag_keeps_its_message() -> Result<(), TestError> {
    let r = refused(
        &[
            "--multi-device",
            "-d",
            "lo,lo",
            "--hep-listen",
            "127.0.0.1:9060",
        ],
        "",
    )?;
    assert_eq!(r.code, 2, "{r:?}");
    assert!(
        r.message
            .contains("--multi-device and --hep-listen/-L cannot run together"),
        "the flag's refusal is unchanged: {r:?}"
    );
    Ok(())
}

/// A file read with `-L` typed is still the security refusal it was.
#[test]
fn failure_an_input_file_with_the_listen_flag_is_still_refused() -> Result<(), TestError> {
    let r = refused(&["-I", CAPTURE, "--hep-listen", "127.0.0.1:9060"], LOOPBACK)?;
    assert_eq!(r.code, 2, "{r:?}");
    assert!(
        r.message
            .contains("--input/-I and --hep-listen/-L cannot run together"),
        "{r:?}"
    );
    Ok(())
}

#[test]
fn failure_an_unknown_key_beside_the_new_ones_is_still_reported() -> Result<(), TestError> {
    let unknown =
        Config::unknown_keys("[hep]\nlisten = \"127.0.0.1:9060\"\nlisten_addr = \"x\"\n")?;
    assert_eq!(
        unknown.len(),
        1,
        "a misspelled key is not accepted because it starts like a real one: {unknown:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Edge: the runs where the key is not the source, and the boundaries.
// ---------------------------------------------------------------------------

/// A run that reads a capture file is not a listener run. The key must not
/// turn `sipnab -I capture.pcap` into the refused `-I` plus `-L`.
#[test]
fn edge_a_file_read_does_not_use_the_key() -> Result<(), TestError> {
    let run = accepted(&["-I", CAPTURE], LOOPBACK)?;
    assert!(
        matches!(run.plan.source, Some(CaptureSource::File { .. })),
        "the source is the file: {:?}",
        run.plan.source.as_ref().map(CaptureSource::label)
    );
    assert_eq!(
        run.cli.hep_listen(&run.config),
        None,
        "no listener in a run that reads a file"
    );
    Ok(())
}

#[test]
fn edge_a_file_read_says_the_key_is_not_used() -> Result<(), TestError> {
    let run = accepted(&["-I", CAPTURE], LOOPBACK)?;
    let warnings = run.cli.inert_key_warnings(&run.config);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("[hep] listen") && w.contains("-I")),
        "the run says why no listener started: {warnings:?}"
    );
    Ok(())
}

#[test]
fn edge_a_file_read_does_not_check_the_keys_bind_policy() -> Result<(), TestError> {
    let run = accepted(&["-I", CAPTURE], "[hep]\nlisten = \"192.0.2.10:9060\"\n")?;
    assert!(
        listeners(run.plan.source.as_ref()).is_empty(),
        "a listener that does not start is not held to the bind policy"
    );
    Ok(())
}

#[test]
fn edge_no_config_ignores_the_keys() -> Result<(), TestError> {
    let cli = Cli::try_parse_from_args(["sipnab", "-N", "-F"])?;
    let loaded = load_config(&cli).map_err(|e| e.message)?;
    assert_eq!(
        cli.hep_listen(&loaded.config),
        None,
        "-F reads no file, so no key starts a listener"
    );
    Ok(())
}

#[test]
fn edge_a_file_without_the_hep_section_plans_no_listener() -> Result<(), TestError> {
    let cli = Cli::try_parse_from_args(["sipnab", "-N", "-F"])?;
    let config: Config = toml::from_str("[display]\ncolor = \"never\"\n")?;
    assert_eq!(
        cli.hep_listen(&config),
        None,
        "no key, no flag, no listener"
    );
    assert!(cli.hep_allow(&config).is_empty(), "and no allowlist");
    Ok(())
}

#[test]
fn edge_an_empty_allow_list_is_no_allowlist() -> Result<(), TestError> {
    let run = accepted(&[], "[hep]\nlisten = \"127.0.0.1:9060\"\nallow = []\n")?;
    assert_eq!(
        listener(&run)?.1,
        0,
        "an empty list admits by the bind policy alone"
    );
    Ok(())
}

#[test]
fn edge_an_empty_allow_list_does_not_satisfy_the_bind_policy() -> Result<(), TestError> {
    let r = refused(&[], "[hep]\nlisten = \"192.0.2.10:9060\"\nallow = []\n")?;
    assert_eq!(r.code, 1, "a routable bind with an empty allowlist: {r:?}");
    Ok(())
}

#[test]
fn edge_the_allow_key_alone_starts_nothing_and_says_so() -> Result<(), TestError> {
    let run = accepted(&["-d", "lo"], "[hep]\nallow = [\"198.51.100.0/24\"]\n")?;
    assert!(
        listeners(run.plan.source.as_ref()).is_empty(),
        "an allowlist is not a listener"
    );
    let warnings = run.cli.inert_key_warnings(&run.config);
    assert!(
        warnings.iter().any(|w| w.contains("[hep] allow")),
        "the run says the allowlist does nothing: {warnings:?}"
    );
    Ok(())
}

#[test]
fn edge_the_allow_key_is_not_inert_with_the_listen_flag() -> Result<(), TestError> {
    let run = accepted(
        &["--hep-listen", "127.0.0.1:9060"],
        "[hep]\nallow = [\"198.51.100.0/24\"]\n",
    )?;
    let warnings = run.cli.inert_key_warnings(&run.config);
    assert!(
        !warnings.iter().any(|w| w.contains("[hep] allow")),
        "the allowlist applies to the listener the flag starts: {warnings:?}"
    );
    Ok(())
}

#[test]
fn edge_a_single_host_allow_entry_is_one_source() -> Result<(), TestError> {
    let run = accepted(
        &[],
        "[hep]\nlisten = \"192.0.2.10:9060\"\nallow = [\"203.0.113.7\"]\n",
    )?;
    assert_eq!(listener(&run)?.1, 1, "a bare address is one host");
    Ok(())
}

#[test]
fn edge_an_ipv6_allow_entry_is_accepted() -> Result<(), TestError> {
    let run = accepted(
        &[],
        "[hep]\nlisten = \"192.0.2.10:9060\"\nallow = [\"2001:db8::/32\"]\n",
    )?;
    assert_eq!(listener(&run)?.1, 1, "an RFC 3849 prefix");
    Ok(())
}

#[test]
fn edge_port_zero_in_the_key_is_planned_as_written() -> Result<(), TestError> {
    let run = accepted(&[], "[hep]\nlisten = \"127.0.0.1:0\"\n")?;
    assert_eq!(
        listener(&run)?.0,
        "127.0.0.1:0",
        "the system picks the port at bind"
    );
    Ok(())
}

#[test]
fn edge_the_key_keeps_surrounding_text_out_of_the_address() -> Result<(), TestError> {
    let r = refused(&[], "[hep]\nlisten = \" 127.0.0.1:9060\"\n")?;
    assert_eq!(
        r.code, 1,
        "a leading space is not part of an address: {r:?}"
    );
    assert!(r.message.contains("[hep] listen"), "names the key: {r:?}");
    Ok(())
}

#[test]
fn edge_the_flag_with_the_same_value_as_the_key_is_one_listener() -> Result<(), TestError> {
    let run = accepted(&["--hep-listen", "127.0.0.1:9060"], LOOPBACK)?;
    assert_eq!(
        listeners(run.plan.source.as_ref()).len(),
        1,
        "the flag replaces the key; the two are not two listeners"
    );
    Ok(())
}

#[test]
fn edge_the_other_hep_keys_still_load_beside_the_new_ones() -> Result<(), TestError> {
    let run = accepted(
        &[],
        "[hep]\nlisten = \"127.0.0.1:9060\"\nsend_queue_mib = 8\nsend_timeout_secs = 9\n",
    )?;
    assert_eq!(
        run.config.hep.send_queue_mib,
        Some(8),
        "an older key in the same section"
    );
    assert_eq!(listener(&run)?.0, "127.0.0.1:9060", "and the new one");
    Ok(())
}

#[test]
fn edge_the_default_config_has_neither_key() {
    let config = Config::default();
    assert_eq!(config.hep.listen, None, "no listener by default");
    assert!(config.hep.allow.is_empty(), "no allowlist by default");
}

#[test]
fn edge_explicit_off_per_peer_limit_needs_no_listener() -> Result<(), TestError> {
    let run = accepted(&["-d", "lo", "--hep-rate-limit-per-peer", "off"], "")?;
    assert!(
        listeners(run.plan.source.as_ref()).is_empty(),
        "`off` is the default and asks for nothing"
    );
    Ok(())
}

#[test]
fn edge_the_per_peer_auto_limit_divides_by_the_keys_allowlist() -> Result<(), TestError> {
    let run = accepted(
        &[
            "--hep-rate-limit",
            "1000",
            "--hep-rate-limit-per-peer",
            "auto",
        ],
        ROUTABLE,
    )?;
    let per_peer = match run.plan.source {
        Some(CaptureSource::Hep {
            per_peer_rate_limit,
            ..
        }) => per_peer_rate_limit,
        _ => return Err("the run planned no single HEP listener".into()),
    };
    assert_eq!(
        per_peer, 500,
        "auto divides the 1000 ceiling by the two sources [hep] allow names"
    );
    Ok(())
}

#[test]
fn edge_the_listener_only_refusal_lists_every_flag_given() -> Result<(), TestError> {
    let r = refused(&["--hep-senders", "--th-mappings"], "")?;
    assert!(
        r.message.contains("--hep-senders") && r.message.contains("--th-mappings"),
        "one refusal names both flags, so one fix covers both: {r:?}"
    );
    Ok(())
}
