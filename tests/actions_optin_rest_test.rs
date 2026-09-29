// SPDX-License-Identifier: MIT OR Apache-2.0

//! sipnab changes no external system unless the operator enables it (REST).
//!
//! Written before the behavior exists. Until it did, `POST /v1/tfps/ban` and
//! `/v1/tfps/unban` ran `tfps_ctl` for any credential that could read, on any
//! host where TFPS was installed. Norm, 2026-09-28: "Default is secure, sipnab
//! doesn't update external systems. With config settings, MCP, REST, updates
//! to fail2ban, tfps, etc can be enabled."
//!
//! Two locks, both required to act:
//!
//! * the server enables the action for this surface, with
//!   `--allow-action tfps:rest` or `[actions] tfps = ["rest"]`;
//! * the caller presents a token minted with scope `actions`. A `full` token,
//!   and a static `--api-key` (which is `full`), read everything and act on
//!   nothing.
//!
//! Every refusal is checked for its effect, not only its status: the fake
//! `tfps_ctl` records each call, and a refused request must leave no record.

#![cfg(all(unix, feature = "full"))]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[path = "support/server.rs"]
mod server;

use server::ApiServer;

const SIGNING_KEY: &str = "actions-optin-rest-test-signing-key";
const BAN: &str = r#"{"ip":"198.51.100.20","action":"ban","applied":true,"refused":null,"expires":null,"source":"operator"}"#;
const UNBAN: &str = r#"{"ip":"198.51.100.20","action":"unban","applied":true,"refused":null,"expires":null,"source":"operator"}"#;
const BANNED: &str = include_str!("fixtures/tfps-banned-golden.jsonl");

/// A `tfps_ctl` that answers ban, unban and banned, and records every call.
struct Fake {
    dir: tempfile::TempDir,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let here = dir.path().display();
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" >> \"{here}/argv\"\n\
             case \"$1\" in\n\
             ban) echo '{BAN}';;\n\
             unban) echo '{UNBAN}';;\n\
             banned) cat <<'SIPNAB_FIXTURE'\n{BANNED}\nSIPNAB_FIXTURE\n;;\n\
             *) echo \"unknown subcommand $1\" >&2; exit 2;;\n\
             esac\n"
        );
        let path = dir.path().join("tfps_ctl");
        std::fs::write(&path, script).expect("write the fake");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        Self { dir }
    }

    fn path(&self) -> String {
        self.dir.path().join("tfps_ctl").display().to_string()
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("argv")).unwrap_or_default()
    }

    /// Whether `tfps_ctl <subcommand>` ran, matched on the whole argv line:
    /// `banned`, which reads, must not count as `ban`.
    fn ran(&self, subcommand: &str) -> bool {
        self.calls().lines().any(|l| l == subcommand)
    }
}

fn token(scope: &str) -> String {
    sipnab::auth::mint(
        SIGNING_KEY.as_bytes(),
        &format!("actions-test-{scope}"),
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        scope,
    )
}

fn server(fake: &Fake, extra: &[&str]) -> ApiServer {
    let path = fake.path();
    let journal = fake.dir.path().join("journal").display().to_string();
    let mut args = vec![
        "--api-signing-key",
        SIGNING_KEY,
        "--tfps-ctl",
        path.as_str(),
        "--journal-dir",
        journal.as_str(),
    ];
    args.extend_from_slice(extra);
    ApiServer::spawn(&args)
}

const BAN_BODY: &str = r#"{"ip":"198.51.100.20"}"#;

/// With nothing enabled, even an `actions` token changes nothing, and the
/// refusal names the setting that would enable it.
#[test]
fn by_default_no_token_can_ban_or_unban() {
    let fake = Fake::new();
    let srv = server(&fake, &[]);
    let actions = token(sipnab::auth::SCOPE_ACTIONS);
    for route in ["/v1/tfps/ban", "/v1/tfps/unban"] {
        let resp = srv.post_json_bearer(route, BAN_BODY, &actions);
        assert_eq!(resp.status, 403, "POST {route}: {}", resp.body);
        assert!(
            resp.body.contains("--allow-action tfps:rest") && resp.body.contains("[actions]"),
            "the refusal names how to enable it: {}",
            resp.body
        );
    }
    assert_eq!(fake.calls(), "", "a refused action reached tfps_ctl");
}

/// Enabled for REST, an `actions` token acts.
#[test]
fn enabled_for_rest_an_actions_token_bans_and_unbans() {
    let fake = Fake::new();
    // An address rests between actions; a second is enough here.
    let config = fake.dir.path().join("sipnab.toml");
    std::fs::write(&config, "[action_limits]\naddress_cooldown_secs = 1\n").expect("config");
    let config = config.display().to_string();
    let srv = server(&fake, &["--allow-action", "tfps:rest", "--config", &config]);
    let actions = token(sipnab::auth::SCOPE_ACTIONS);
    let ban = srv.post_json_bearer("/v1/tfps/ban", BAN_BODY, &actions);
    assert_eq!(ban.status, 200, "{}", ban.body);
    assert_eq!(ban.json()["applied"], true, "{}", ban.body);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let unban = srv.post_json_bearer("/v1/tfps/unban", BAN_BODY, &actions);
    assert_eq!(unban.status, 200, "{}", unban.body);
    assert!(fake.ran("ban") && fake.ran("unban"), "{}", fake.calls());
    assert!(
        fake.calls().contains("ban\n--json\n198.51.100.20"),
        "{}",
        fake.calls()
    );
}

/// Enabled, a `full` token and a static key still read everything and act on
/// nothing: reading must not imply acting.
#[test]
fn enabled_a_full_token_or_static_key_cannot_act() {
    let fake = Fake::new();
    let srv = server(
        &fake,
        &["--allow-action", "tfps:rest", "--api-key", "static-key"],
    );
    for credential in [token(sipnab::auth::SCOPE_FULL), "static-key".to_string()] {
        let resp = srv.post_json_bearer("/v1/tfps/ban", BAN_BODY, &credential);
        assert_eq!(resp.status, 401, "{}", resp.body);
        let read = srv.get_bearer("/v1/tfps/banned", &credential);
        assert_eq!(read.status, 200, "reading still works: {}", read.body);
    }
    assert!(fake.ran("banned"), "the reads ran: {}", fake.calls());
    assert!(
        !fake.ran("ban"),
        "a credential without the actions scope reached tfps_ctl: {}",
        fake.calls()
    );
}

/// Enabled for MCP only, REST stays refused.
#[test]
fn enabled_for_mcp_only_rest_stays_refused() {
    let fake = Fake::new();
    let srv = server(&fake, &["--allow-action", "tfps:mcp"]);
    let resp = srv.post_json_bearer(
        "/v1/tfps/ban",
        BAN_BODY,
        &token(sipnab::auth::SCOPE_ACTIONS),
    );
    assert_eq!(resp.status, 403, "{}", resp.body);
    assert_eq!(fake.calls(), "");
}

/// The config file enables it the same way the flag does.
#[test]
fn the_config_file_enables_it_like_the_flag() {
    let fake = Fake::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let config: PathBuf = dir.path().join("sipnab.toml");
    std::fs::write(&config, "[actions]\ntfps = [\"rest\"]\n").expect("write config");
    let config = config.display().to_string();
    let srv = server(&fake, &["--config", &config]);
    let resp = srv.post_json_bearer(
        "/v1/tfps/ban",
        BAN_BODY,
        &token(sipnab::auth::SCOPE_ACTIONS),
    );
    assert_eq!(resp.status, 200, "{}", resp.body);
    assert!(fake.ran("ban"), "{}", fake.calls());
}

/// A value naming no known target or surface is refused at startup rather
/// than read as "nothing enabled".
#[test]
fn an_unknown_target_or_surface_is_refused_at_startup() {
    for bad in ["fail2ban:rest", "tfps:web", "tfps"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args([
                "-N",
                "-I",
                "tests/fixtures/sip_call.pcap",
                "--allow-action",
                bad,
            ])
            .output()
            .expect("run sipnab");
        assert!(!out.status.success(), "{bad:?} must be refused");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("--allow-action"), "{bad:?}: {stderr}");
    }
}
