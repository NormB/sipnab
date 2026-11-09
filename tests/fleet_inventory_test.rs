// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The fleet inventory end to end: real `sipnab --api` processes, the
//! `GET /v1/inventory` route, the MCP `fleet_inventory` tool, and
//! `sipnab fleet inventory` reading two instances and one that is down.
//!
//! In `tests/` because it needs the built binary and more than one process.
#![cfg(all(feature = "api", feature = "mcp"))]

use std::io::Write as _;
use std::process::Command;

use server::TestError;

#[path = "support/server.rs"]
mod server;

#[path = "support/mcp.rs"]
mod mcp;

#[path = "support/ports.rs"]
mod ports;

use server::ApiServer;

/// The signing key every instance here verifies tokens with.
const KEY: &str = "fleet-inventory-e2e-signing-key-0123456789";

/// A value that stands for a secret: it is put in a configuration file and
/// on a command line, and must appear in no inventory output.
const SECRET: &str = "s3cr3t-fleet-marker-5f1c2a9e";

/// An independent SHA-256 in hex.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A token for the inventory, from [`KEY`].
fn inventory_token() -> String {
    sipnab::auth::mint(
        KEY.as_bytes(),
        "fleet-e2e",
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_INVENTORY,
    )
}

/// A config file in `dir` whose one value is `value`.
fn config_file(
    dir: &std::path::Path,
    name: &str,
    value: &str,
) -> Result<(std::path::PathBuf, String), TestError> {
    let text = format!("# fleet test\n[vcon_forward]\nauth_file = \"/run/example/{value}\"\n");
    let path = dir.join(name);
    std::fs::write(&path, &text)?;
    Ok((path, text))
}

/// An instance with node name `node` and config `config`.
fn instance(node: &str, config: &std::path::Path) -> Result<ApiServer, TestError> {
    let config = config.to_str().ok_or("utf-8 path")?;
    ApiServer::spawn(&[
        "--api-signing-key",
        KEY,
        "--node-name",
        node,
        "--config",
        config,
    ])
}

/// A token file in `dir`, readable by this user only.
fn token_file(
    dir: &std::path::Path,
    name: &str,
    token: &str,
) -> Result<std::path::PathBuf, TestError> {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    writeln!(f, "{token}")?;
    Ok(path)
}

/// `sipnab fleet inventory --json` over `hosts`: exit code, stdout, stderr.
fn fleet(hosts: &std::path::Path, json: bool) -> Result<(i32, String, String), TestError> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.args(["fleet", "inventory", "--hosts"]).arg(hosts);
    cmd.args(["--timeout", "5"]);
    if json {
        cmd.arg("--json");
    }
    let out = cmd.output()?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout)?,
        String::from_utf8(out.stderr)?,
    ))
}

/// The route reports this build, the running binary's digest, the
/// configuration's digests and the node name; and the signature as
/// unverified.
#[test]
fn the_route_reports_build_binary_and_config_digests() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (path, text) = config_file(dir.path(), "a.toml", "edge-a.cred")?;
    let srv = instance("edge-a", &path)?;
    let resp = srv.get_bearer("/v1/inventory", &inventory_token())?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    let v = resp.json()?;
    assert_eq!(v["schema_version"], 1, "{v}");
    assert_eq!(v["node_name"], "edge-a", "{v}");
    assert_eq!(
        v["build"]["version_line"],
        sipnab::cli::build_version(),
        "{v}"
    );
    let exe = std::fs::read(env!("CARGO_BIN_EXE_sipnab"))?;
    assert_eq!(v["binary"]["sha256"], sha256_hex(&exe), "{v}");
    assert_eq!(v["signature"]["state"], "unverified", "{v}");
    assert_eq!(v["config"]["recorded"], true, "{v}");
    assert_eq!(v["config"]["source"], path.display().to_string(), "{v}");
    assert_eq!(
        v["config"]["file_sha256"],
        sha256_hex(text.as_bytes()),
        "{v}"
    );
    let parsed: sipnab::config::Config = toml::from_str(&text)?;
    assert_eq!(
        v["config"]["parsed_sha256"],
        sipnab::output::inventory::parsed_config_digest(&parsed)?,
        "{v}"
    );
    assert_eq!(v["process"]["pid"], srv.pid(), "{v}");
    let argv = v["config"]["argv_sha256"].as_str().ok_or("argv digest")?;
    assert_eq!(
        v["config"]["effective_sha256"].as_str(),
        sipnab::output::inventory::effective_digest(v["config"]["parsed_sha256"].as_str(), argv)
            .as_deref(),
        "{v}"
    );

    // The build fields agree with what the same binary prints for
    // `--version`, a source the route does not share with this test.
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("--version")
        .output()?;
    let printed = String::from_utf8(out.stdout)?;
    let first = printed.lines().next().ok_or("a --version line")?;
    let line = v["build"]["version_line"].as_str().ok_or("version_line")?;
    assert_eq!(first, format!("sipnab {line}"), "{v}");
    let version = v["build"]["version"].as_str().ok_or("version")?;
    assert!(
        first.starts_with(&format!("sipnab {version}")),
        "{first} vs {v}"
    );
    // `--version` prints `X.Y.Z (TAG COMMIT[-dirty]) features: ...`, or no
    // parenthesis when the build recorded no commit.
    let printed_commit = first
        .split_once(" (")
        .and_then(|(_, rest)| rest.split_once(')'))
        .and_then(|(inside, _)| inside.split(' ').next_back())
        .map_or("", |c| c.trim_end_matches("-dirty"));
    assert_eq!(v["build"]["commit"], printed_commit, "{first} vs {v}");
    assert_eq!(
        v["build"]["dirty"],
        first.contains("-dirty)"),
        "{first} vs {v}"
    );
    let features: Vec<&str> = v["build"]["features"]
        .as_array()
        .ok_or("features")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let mut printed_features: Vec<&str> = first
        .split(" features: ")
        .nth(1)
        .ok_or("a features part")?
        .split(',')
        .collect();
    printed_features.sort_unstable();
    assert_eq!(features, printed_features, "{first} vs {v}");
    Ok(())
}

/// The REST route and the MCP tool return the same record for one process
/// state.
#[tokio::test]
async fn rest_and_mcp_return_the_same_record() -> Result<(), TestError> {
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use parking_lot::{Mutex, RwLock};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use tower::ServiceExt as _;

    let dialogs = Arc::new(RwLock::new(sipnab::sip::dialog_store::DialogStore::new(
        100, false,
    )));
    let streams = Arc::new(RwLock::new(sipnab::rtp::stream_store::StreamStore::new(
        100,
    )));
    // A start well in the past, so each door's uptime shows it read the
    // start it was given and not its own construction time.
    let started = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(100))
        .ok_or("a start 100 s ago")?;
    let interfaces = vec!["lo".to_string()];
    // The first record of a process hashes its binary, which under a loaded
    // test run takes seconds. Taken here, so neither door's read waits on it
    // and the two reads are close enough in time to compare.
    let _ = sipnab::output::inventory::current(None, &[], 0);
    // One capture meter for both doors, carrying a HEP roster where the
    // build has a listener, so the sender list is compared too.
    #[cfg(feature = "hep")]
    let meter = Some(roster("192.0.2.10", "198.51.100.66")?);
    #[cfg(not(feature = "hep"))]
    let meter: Option<sipnab::capture::channel::CaptureMeter> = None;
    let state = sipnab::output::api::ApiState {
        relay_query: Default::default(),
        alias_thresholds: Default::default(),
        dialog_store: dialogs.clone(),
        stream_store: streams.clone(),
        verifier: Arc::new(sipnab::auth::TokenVerifier::new(
            sipnab::auth::VerifierConfig {
                static_keys: vec![KEY.to_string()],
                ..Default::default()
            },
        )),
        rate_limiter: Arc::new(Mutex::new(sipnab::output::api::RateLimiter::new(
            1000, 1024,
        ))),
        max_inline_media_bytes: None,
        content_deny_header: None,
        max_rows: 1000,
        capture: None,
        source_exhausted: None,
        capture_interfaces: interfaces.clone(),
        capture_meter: meter.clone(),
        started_at: started,
        persistence_gate: Arc::new(sipnab::output::persistence::PersistenceGate::new(false)),
        tfps: Default::default(),
        actions: Default::default(),
        alert_engine: None,
        armed_detections: Vec::new(),
        scanner_response: Default::default(),
        file_root: None,
        vcon_spools: Vec::new(),
        vcon_fetch: Default::default(),
        live_audio: Arc::default(),
        pipeline_options: Default::default(),
        archive: sipnab::output::api::ArchivePasswordPolicy::default(),
    };
    let mut req = Request::builder()
        .uri("/v1/inventory")
        .header("Authorization", format!("Bearer {KEY}"))
        .body(Body::empty())?;
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        40000,
    )));
    let resp = sipnab::output::api::build_router(state)
        .oneshot(req)
        .await?;
    assert_eq!(
        resp.status(),
        200,
        "the REST route answers an inventory token"
    );
    let rest: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await?.to_bytes())?;

    let mut srv = sipnab::mcp::server::SipnabMcp::new(dialogs, streams)
        .with_capture_interfaces(interfaces)
        .with_capture_meter(meter);
    srv.started_at = started;
    let result = srv
        .fleet_inventory()
        .await
        .map_err(|e| format!("the tool answers: {e:?}"))?;
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text())
        .map(|t| t.text.clone())
        .ok_or("a JSON block")?;
    let mut mcp: serde_json::Value = serde_json::from_str(&text)?;
    // Uptime is the one field that moves between the two reads, which can
    // straddle a second boundary. Both must come from `started`, and every
    // other field must be equal.
    let mut rest = rest;
    let up = |v: &mut serde_json::Value| v["process"]["uptime_seconds"].take().as_u64();
    let (rest_up, mcp_up) = (
        up(&mut rest).ok_or("REST uptime")?,
        up(&mut mcp).ok_or("MCP uptime")?,
    );
    assert!((100..=110).contains(&rest_up), "REST uptime {rest_up}");
    assert!(
        mcp_up >= rest_up && mcp_up - rest_up <= 2,
        "MCP uptime {mcp_up} vs {rest_up}"
    );
    assert_eq!(rest, mcp, "one process, two doors, two answers");
    assert_eq!(rest["interfaces"][0]["name"], "lo", "{rest}");
    assert_eq!(rest["schema_version"], 1, "{rest}");
    #[cfg(feature = "hep")]
    assert_eq!(
        rest["hep_listener"]["senders"].as_array().map(Vec::len),
        Some(2),
        "{rest}"
    );
    Ok(())
}

/// Every JSON pointer in `v` that names an object member, sorted.
fn member_paths(v: &serde_json::Value, at: &str, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, inner) in map {
                let path = format!("{at}/{k}");
                out.push(path.clone());
                member_paths(inner, &path, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, inner) in items.iter().enumerate() {
                member_paths(inner, &format!("{at}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// The real MCP dispatch, not only the tool method: `tools/call
/// fleet_inventory` on a running `sipnab --mcp` answers the document a
/// running `sipnab --api` answers on `GET /v1/inventory`, member for member,
/// and with equal values wherever the two processes are the same (build,
/// binary, configuration file, node name, privilege, signature). Whatever the
/// MCP server adds to every answer on the way out would show here as a
/// member REST does not have.
#[test]
fn the_mcp_dispatch_answers_the_rest_document() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (cfg, _) = config_file(dir.path(), "m.toml", "edge-m.cred")?;
    let cfg_s = cfg.to_str().ok_or("utf-8 path")?;
    let srv = instance("edge-m", &cfg)?;
    let rest = srv.get_bearer("/v1/inventory", &inventory_token())?;
    assert_eq!(rest.status, 200, "{}", rest.body);
    let rest = rest.json()?;

    let pcap = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut session = mcp::McpSession::start(&pcap, &["--config", cfg_s, "--node-name", "edge-m"])?;
    let reply = session.call("fleet_inventory", serde_json::json!({}))?;
    let _ = session.stop();
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .ok_or_else(|| format!("no text block in {reply}"))?;
    let mcp: serde_json::Value = serde_json::from_str(text)?;
    assert_eq!(
        reply["result"]["structuredContent"], mcp,
        "the structured copy is the text block"
    );

    let (mut rest_paths, mut mcp_paths) = (Vec::new(), Vec::new());
    member_paths(&rest, "", &mut rest_paths);
    member_paths(&mcp, "", &mut mcp_paths);
    rest_paths.sort();
    mcp_paths.sort();
    assert_eq!(mcp_paths, rest_paths, "REST {rest}\nMCP {mcp}");
    for same in [
        "/schema_version",
        "/node_name",
        "/build",
        "/binary",
        "/signature",
        "/config/source",
        "/config/file_sha256",
        "/config/parsed_sha256",
        "/config/recorded",
        "/privilege",
        "/hep_listener",
    ] {
        assert_eq!(
            rest.pointer(same),
            mcp.pointer(same),
            "{same}: REST {rest}\nMCP {mcp}"
        );
    }
    Ok(())
}

/// Two instances with different configurations, and one that is down:
/// `sipnab fleet inventory` lists all three, gives each answering instance
/// the digests that instance reports for itself, marks the third
/// unreachable, and exits 1.
#[test]
fn the_fleet_command_reads_two_instances_and_reports_one_down() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (a_cfg, _) = config_file(dir.path(), "a.toml", "edge-a.cred")?;
    let (b_cfg, _) = config_file(dir.path(), "b.toml", "edge-b.cred")?;
    let a = instance("edge-a", &a_cfg)?;
    let b = instance("edge-b", &b_cfg)?;
    let token = inventory_token();
    let tok = token_file(dir.path(), "fleet.token", &token)?;
    let own = |s: &ApiServer| -> Result<serde_json::Value, TestError> {
        s.get_bearer("/v1/inventory", &token)?.json()
    };
    let (a_own, b_own) = (own(&a)?, own(&b)?);
    assert_ne!(
        a_own["config"]["parsed_sha256"], b_own["config"]["parsed_sha256"],
        "the two instances must differ for the comparison to prove anything"
    );
    assert_ne!(
        a_own["config"]["effective_sha256"], b_own["config"]["effective_sha256"],
        "two configurations, two effective digests"
    );

    // Held for the whole test, so no parallel test can be handed the number
    // and listen on it.
    let down_port = ports::refused_tcp_port()?;
    let down = down_port.port();
    let hosts = dir.path().join("hosts.toml");
    let tok = tok.display();
    std::fs::write(
        &hosts,
        format!(
            "[[host]]\nname = \"edge-a\"\nurl = \"http://{}\"\ntoken_file = \"{tok}\"\n\
             [[host]]\nname = \"edge-b\"\nurl = \"http://{}\"\ntoken_file = \"{tok}\"\n\
             [[host]]\nname = \"edge-down\"\nurl = \"http://127.0.0.1:{down}\"\ntoken_file = \"{tok}\"\n",
            a.addr, b.addr
        ),
    )?;
    let (code, out, err) = fleet(&hosts, true)?;
    assert_eq!(code, 1, "one host is down: stdout {out}\nstderr {err}");
    let report: serde_json::Value = serde_json::from_str(&out)?;
    let rows = report["hosts"].as_array().ok_or("hosts")?;
    assert_eq!(rows.len(), 3, "{report}");
    assert_eq!(rows[0]["name"], "edge-a", "rows keep the hosts-file order");
    assert_eq!(rows[0]["state"], "ok", "{report}");
    assert_eq!(rows[1]["state"], "ok", "{report}");
    assert_eq!(
        rows[2]["name"], "edge-down",
        "the host that is down is still listed"
    );
    assert_eq!(rows[2]["state"], "unreachable", "{report}");
    assert_eq!(report["ok"], false, "a host down makes the report not ok");
    for (row, own) in [(&rows[0], &a_own), (&rows[1], &b_own)] {
        let inv = &row["inventory"];
        assert_eq!(inv["node_name"], own["node_name"], "{report}");
        assert_eq!(
            inv["config"]["parsed_sha256"], own["config"]["parsed_sha256"],
            "each row's parsed digest is the one that instance reports itself"
        );
        assert_eq!(
            inv["config"]["effective_sha256"], own["config"]["effective_sha256"],
            "each row's effective digest is the one that instance reports itself"
        );
        assert_eq!(
            inv["config"]["file_sha256"], own["config"]["file_sha256"],
            "each row's file digest is the one that instance reports itself"
        );
        assert_eq!(
            inv["binary"]["sha256"], own["binary"]["sha256"],
            "each row's binary digest is the one that instance reports itself"
        );
    }
    assert_eq!(
        rows[0]["inventory"]["node_name"], "edge-a",
        "the first row is edge-a's inventory"
    );
    assert_eq!(
        rows[1]["inventory"]["node_name"], "edge-b",
        "the second row is edge-b's inventory"
    );

    // The two that answer alone are a healthy fleet: exit 0, no finding.
    std::fs::write(
        &hosts,
        format!(
            "[[host]]\nname = \"edge-a\"\nurl = \"http://{}\"\ntoken_file = \"{tok}\"\n\
             [[host]]\nname = \"edge-b\"\nurl = \"http://{}\"\ntoken_file = \"{tok}\"\n",
            a.addr, b.addr
        ),
    )?;
    let (code, out, err) = fleet(&hosts, false)?;
    assert_eq!(code, 0, "stdout {out}\nstderr {err}");
    // The table's CONFIG column is each instance's own effective digest.
    for (name, own) in [("edge-a", &a_own), ("edge-b", &b_own)] {
        let row = out
            .lines()
            .find(|l| l.starts_with(name))
            .ok_or_else(|| format!("no {name} row in\n{out}"))?;
        let digest = own["config"]["effective_sha256"].as_str().ok_or("digest")?;
        assert!(row.contains(&digest[..12]), "{name}: {digest} not in {row}");
    }
    Ok(())
}

/// A secret in an instance's configuration and on its command line, and
/// the controller's own token, appear in no output: not the REST body, not
/// the MCP tool's answer, not the fleet command's stdout or stderr in either
/// format, not the instance's log. A refused instance's error does not quote
/// the token either.
#[test]
fn no_secret_appears_in_any_inventory_output() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (cfg, _) = config_file(dir.path(), "s.toml", SECRET)?;
    let cfg_s = cfg.to_str().ok_or("utf-8 path")?;
    let api_key = format!("{SECRET}-api-key");
    let srv = ApiServer::spawn(&[
        "--api-signing-key",
        KEY,
        "--api-key",
        &api_key,
        "--node-name",
        "edge-s",
        "--config",
        cfg_s,
    ])?;
    let token = inventory_token();
    let mut outputs: Vec<(String, String)> = Vec::new();

    let rest = srv.get_bearer("/v1/inventory", &token)?;
    assert_eq!(rest.status, 200, "{}", rest.body);
    outputs.push(("REST body".into(), rest.body.clone()));
    outputs.push(("instance log".into(), srv.startup_log.clone()));

    let pcap = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut session = mcp::McpSession::start(&pcap, &["--config", cfg_s])?;
    let tool = session.call("fleet_inventory", serde_json::json!({}))?;
    outputs.push(("MCP answer".into(), tool.to_string()));
    assert!(tool["result"]["isError"] != true, "{tool}");
    let _ = session.stop();

    let tok = token_file(dir.path(), "fleet.token", &token)?;
    let bad = token_file(dir.path(), "bad.token", &format!("{SECRET}-wrong-token"))?;
    let hosts = dir.path().join("hosts.toml");
    std::fs::write(
        &hosts,
        format!(
            "[[host]]\nname = \"edge-s\"\nurl = \"http://{}\"\ntoken_file = \"{}\"\n\
             [[host]]\nname = \"edge-refused\"\nurl = \"http://{}\"\ntoken_file = \"{}\"\n",
            srv.addr,
            tok.display(),
            srv.addr,
            bad.display()
        ),
    )?;
    for json in [true, false] {
        let (code, out, err) = fleet(&hosts, json)?;
        assert_eq!(code, 1, "one host refuses: {out}\n{err}");
        assert!(out.contains("refused"), "{out}");
        outputs.push((format!("fleet stdout json={json}"), out));
        outputs.push((format!("fleet stderr json={json}"), err));
    }

    let inv: serde_json::Value = serde_json::from_str(&rest.body)?;
    assert!(
        inv["config"]["parsed_sha256"].is_string(),
        "the digest is there: {inv}"
    );

    // The same instance with only the secret changed reports a different
    // effective digest, and the same parsed one.
    let rotated_key = format!("{SECRET}-rotated");
    let rotated = ApiServer::spawn(&[
        "--api-signing-key",
        KEY,
        "--api-key",
        &rotated_key,
        "--node-name",
        "edge-s",
        "--config",
        cfg_s,
    ])?;
    let rotated_body = rotated.get_bearer("/v1/inventory", &token)?;
    assert_eq!(rotated_body.status, 200, "{}", rotated_body.body);
    outputs.push(("rotated REST body".into(), rotated_body.body.clone()));
    let rot: serde_json::Value = serde_json::from_str(&rotated_body.body)?;
    assert_eq!(
        rot["config"]["parsed_sha256"], inv["config"]["parsed_sha256"],
        "the collector is listening with a roster"
    );
    assert_ne!(
        rot["config"]["effective_sha256"], inv["config"]["effective_sha256"],
        "a changed secret kept the effective digest"
    );
    assert!(rot["config"]["effective_sha256"].is_string(), "{rot}");
    for (name, text) in &outputs {
        assert!(!text.contains(SECRET), "{name} carries the secret:\n{text}");
        assert!(
            !text.contains(&token),
            "{name} carries the controller's token:\n{text}"
        );
    }
    Ok(())
}

/// The fleet command refuses a token file other users can read, without
/// quoting it, and a hosts file it cannot use, with exit 2.
#[test]
fn the_fleet_command_refuses_unsafe_or_unusable_input() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let hosts = dir.path().join("hosts.toml");
    std::fs::write(&hosts, "[[host]]\nname = \"a\"\n")?;
    let (code, _, err) = fleet(&hosts, false)?;
    assert_eq!(code, 2, "{err}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let closed = ports::refused_tcp_port()?;
        let open = dir.path().join("open.token");
        std::fs::write(&open, format!("{SECRET}\n"))?;
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644))?;
        std::fs::write(
            &hosts,
            format!(
                "[[host]]\nname = \"a\"\nurl = \"http://127.0.0.1:{}\"\ntoken_file = \"{}\"\n",
                closed.port(),
                open.display()
            ),
        )?;
        let (code, out, err) = fleet(&hosts, true)?;
        assert_eq!(code, 1, "{out}\n{err}");
        let report: serde_json::Value = serde_json::from_str(&out)?;
        let error = report["hosts"][0]["error"].as_str().unwrap_or_default();
        assert!(error.contains("open.token"), "{report}");
        assert!(
            !out.contains(SECRET) && !err.contains(SECRET),
            "{out}\n{err}"
        );
    }
    Ok(())
}

/// A HEP roster with one sender at `listed`, one at `stray`, both admitted
/// on a frozen clock.
#[cfg(feature = "hep")]
fn roster(listed: &str, stray: &str) -> Result<sipnab::capture::channel::CaptureMeter, TestError> {
    use sipnab::capture::hep_roster::{HepRoster, RosterState, SenderTrust, hep_source_label};
    let t = std::time::Instant::now();
    let wall = chrono::DateTime::from_timestamp(1_790_000_000, 0).ok_or("a time")?;
    let mut state = RosterState::new(
        SenderTrust::SharedSecretPlain,
        4096,
        std::time::Duration::from_secs(30),
        t,
        wall,
    );
    for (id, peer) in [(7, listed), (9, stray)] {
        let peer: std::net::IpAddr = peer.parse()?;
        state.admitted(Some(id), peer, &hep_source_label(Some(id), peer), t);
    }
    let frozen = t + std::time::Duration::from_secs(1);
    let (_tx, rx) = sipnab::capture::channel::packet_channel(8);
    let meter = rx.meter();
    if !meter.attach_hep_roster(HepRoster::with_clock(
        state,
        std::sync::Arc::new(move || frozen),
    )) {
        return Err("a fresh meter takes a roster".into());
    }
    Ok(meter)
}

/// The cross-check end to end, from the listener's roster: a collector's
/// inventory, built by the one builder both surfaces call, lists its HEP
/// senders; `merge` flags the sender no listed instance's address
/// accounts for, naming the collector and the address, and not the one
/// that is listed.
#[cfg(feature = "hep")]
#[test]
fn a_roster_sender_missing_from_the_inventory_is_flagged() -> Result<(), TestError> {
    use sipnab::app::fleet::{Answer, HostResult, merge};
    let meter = roster("192.0.2.10", "198.51.100.66")?;
    let hub = sipnab::output::inventory::current(Some(&meter), &[], 5);
    let hub = serde_json::to_value(&hub)?;
    assert_eq!(hub["hep_listener"]["listening"], true, "{hub}");
    let edge = serde_json::to_value(sipnab::output::inventory::current(None, &[], 5))?;
    let report = merge(vec![
        HostResult {
            name: "edge-a".into(),
            url: "http://192.0.2.10:8080".into(),
            addresses: vec!["192.0.2.10".parse()?],
            answer: Answer::Inventory(edge),
        },
        HostResult {
            name: "hub".into(),
            url: "http://192.0.2.1:8080".into(),
            addresses: vec!["192.0.2.1".parse()?],
            answer: Answer::Inventory(hub),
        },
    ]);
    assert!(!report.ok, "{report:?}");
    let stray: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.kind == "unlisted_hep_sender")
        .collect();
    assert_eq!(stray.len(), 1, "{:?}", report.findings);
    assert!(stray[0].detail.contains("198.51.100.66"), "{:?}", stray[0]);
    assert!(stray[0].detail.contains("hub"), "{:?}", stray[0]);
    assert!(!stray[0].detail.contains("192.0.2.10"), "{:?}", stray[0]);
    Ok(())
}

/// Every hosts file `docs/fleet.md` shows parses with the command's own
/// parser, so a reader who copies one gets a file `sipnab fleet inventory`
/// accepts.
#[test]
fn the_documented_hosts_files_parse() -> Result<(), TestError> {
    let page = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/fleet.md"))?;
    let mut parsed = 0;
    let mut rest = page.as_str();
    while let Some(at) = rest.find("```toml\n") {
        let body_start = at + "```toml\n".len();
        let body_len = rest[body_start..]
            .find("```")
            .ok_or("an unterminated toml fence")?;
        let body: String = rest[body_start..body_start + body_len]
            .lines()
            .map(str::trim_start)
            .collect::<Vec<_>>()
            .join("\n");
        rest = &rest[body_start + body_len..];
        if !body.contains("[[host]]") {
            continue;
        }
        let hosts = sipnab::app::fleet::parse_hosts(&body)
            .map_err(|e| format!("docs/fleet.md hosts file does not parse: {e}\n{body}"))?;
        assert!(!hosts.is_empty(), "a documented hosts file names hosts");
        parsed += 1;
    }
    assert!(parsed >= 1, "docs/fleet.md shows a hosts file");
    Ok(())
}

/// A real `sipnab -N --hep-listen --api` collector, for the tests that need a
/// HEP listener and a REST API in one process. Killed when dropped. Gated
/// as its one user is.
#[cfg(all(feature = "hep", target_os = "linux"))]
struct Collector {
    child: std::process::Child,
    /// The REST API's `host:port`.
    api: String,
    /// The HEP listener's `host:port`.
    hep: String,
}

#[cfg(all(feature = "hep", target_os = "linux"))]
impl Collector {
    /// Start one on `ip`, with `extra` on its command line, once both
    /// listeners report the address they bound.
    fn start(ip: &str, extra: &[&str]) -> Result<Self, TestError> {
        use std::io::BufRead as _;
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["-N", "--hep-listen", &format!("{ip}:0")])
            .args(["--api", &format!("{ip}:0"), "--config", "/dev/null"])
            .args(extra)
            .env("SIPNAB_LOG", "info")
            .env("NO_COLOR", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .tied_to_test()
            .spawn()?;
        let stderr = child.stderr.take().ok_or("piped stderr")?;
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                let _ = tx.send(line);
            }
        });
        let (mut api, mut hep) = (None, None);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while (api.is_none() || hep.is_none()) && std::time::Instant::now() < deadline {
            let Ok(line) = rx.recv_timeout(std::time::Duration::from_millis(200)) else {
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(format!("the collector exited early: {status}").into());
                }
                continue;
            };
            if let Some(rest) = line.split("HEP listener started on ").nth(1) {
                hep = rest.split_whitespace().next().map(str::to_string);
            }
            if let Some(rest) = line.split("REST API listening on ").nth(1) {
                api = Some(rest.trim().to_string());
            }
        }
        let collector = Self {
            child,
            api: api.unwrap_or_default(),
            hep: hep.unwrap_or_default(),
        };
        if collector.api.is_empty() || collector.hep.is_empty() {
            return Err("the collector did not report both listeners".into());
        }
        Ok(collector)
    }
}

#[cfg(all(feature = "hep", target_os = "linux"))]
impl Drop for Collector {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `GET path` on `addr` with `token`, as JSON.
#[cfg(all(feature = "hep", target_os = "linux"))]
fn get_json(addr: &str, path: &str, token: &str) -> Result<serde_json::Value, TestError> {
    use std::io::Read as _;
    let mut s = std::net::TcpStream::connect(addr)?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Connection: close\r\n\r\n"
    )?;
    let mut raw = String::new();
    s.read_to_string(&mut raw)?;
    let (head, body) = raw.split_once("\r\n\r\n").ok_or("an HTTP answer")?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!("{path}: {head}").into());
    }
    Ok(serde_json::from_str(body)?)
}

/// FLEET-P0.1, the case seen live: a listed instance sends HEP to a listed
/// collector with a key the collector does not hold, and the collector
/// refuses every packet. `sipnab fleet inventory` used to report that fleet
/// `ok`. Now the report names the collector, the sender and its address,
/// says the packets were refused for authentication without claiming which
/// cause, and exits 1. Left out of the hosts file, the same refused address
/// is no finding: the rule is about listed instances.
///
/// Linux only: the collector listens on 127.0.0.2, so the sender's packets
/// come from 127.0.0.1 and the two instances have different addresses; other
/// systems do not answer on all of 127.0.0.0/8.
#[cfg(all(feature = "hep", target_os = "linux"))]
#[test]
fn a_listed_sender_the_collector_refuses_is_reported_and_exits_1() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let right = token_file(dir.path(), "right.key", "the-collector-hep-key")?;
    let wrong = token_file(dir.path(), "wrong.key", "a-key-the-collector-lacks")?;
    let hub = Collector::start(
        "127.0.0.2",
        &[
            "--hep-allow",
            "127.0.0.0/8",
            "--hep-auth-mode",
            "hmac",
            "--hep-auth-file",
            right.to_str().ok_or("utf-8 path")?,
            "--api-signing-key",
            KEY,
            "--node-name",
            "hub",
        ],
    )?;
    let edge = ApiServer::spawn(&[
        "--api-signing-key",
        KEY,
        "--node-name",
        "edge-a",
        "--hep-send",
        &hub.hep,
        "--hep-auth-mode",
        "hmac",
        "--hep-auth-file",
        wrong.to_str().ok_or("utf-8 path")?,
    ])?;
    let token = inventory_token();
    // The collector's own record, read until the refusals are there, so the
    // command below reads a settled count.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let hub_inv = loop {
        let v = get_json(&hub.api, "/v1/inventory", &token)?;
        let refused = v["hep_listener"]["packets_refused"].as_u64().unwrap_or(0);
        if refused > 0 || std::time::Instant::now() > deadline {
            break v;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let refused = hub_inv["hep_listener"]["packets_refused"]
        .as_u64()
        .unwrap_or(0);
    assert!(refused > 0, "the collector refused nothing: {hub_inv}");
    assert!(
        hub_inv["hep_listener"]["senders"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "a refused sender is no admitted sender: {hub_inv}"
    );

    let tok = token_file(dir.path(), "fleet.token", &token)?;
    let tok = tok.display();
    let hosts = dir.path().join("hosts.toml");
    let hub_row = format!(
        "[[host]]\nname = \"hub\"\nurl = \"http://{}\"\ntoken_file = \"{tok}\"\n",
        hub.api
    );
    let edge_row = format!(
        "[[host]]\nname = \"edge-a\"\nurl = \"http://{}\"\ntoken_file = \"{tok}\"\n",
        edge.addr
    );
    std::fs::write(&hosts, format!("{hub_row}{edge_row}"))?;
    let (code, out, err) = fleet(&hosts, true)?;
    let report: serde_json::Value = serde_json::from_str(&out)?;
    assert_eq!(
        code, 1,
        "a listed sender is refused: stdout {out}\nstderr {err}"
    );
    assert_eq!(report["ok"], false, "{report}");
    let rows = report["hosts"].as_array().ok_or("hosts")?;
    assert!(
        rows.iter().all(|r| r["state"] == "ok"),
        "both instances answer, so only the finding can make the report fail: {report}"
    );
    let findings = report["findings"].as_array().ok_or("findings")?;
    let refused: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["kind"] == "hep_sender_refused")
        .collect();
    assert_eq!(refused.len(), 1, "{report}");
    let detail = refused[0]["detail"].as_str().ok_or("detail")?;
    for want in [
        "hub",
        "edge-a",
        "127.0.0.1",
        "refused: authentication (wrong key or HMAC version)",
        "hmac_bad_mac",
    ] {
        assert!(detail.contains(want), "{want} missing from {detail}");
    }
    let (code, table, _) = fleet(&hosts, false)?;
    assert_eq!(code, 1, "{table}");
    assert!(
        table.contains("finding hep_sender_refused: "),
        "the table names the finding:\n{table}"
    );

    // The collector alone: the refused address is listed by nobody.
    std::fs::write(&hosts, &hub_row)?;
    let (code, out, err) = fleet(&hosts, true)?;
    assert_eq!(
        code, 0,
        "an unlisted refused address is no finding: {out}\n{err}"
    );

    // Fix the sender: the collector's key renamed over its key file, and a
    // restart. The collector still counts the old refusals, but it admitted
    // the sender after them, so the fleet is ok again.
    drop(edge);
    token_file(dir.path(), "fixed.key", "the-collector-hep-key")?;
    std::fs::rename(dir.path().join("fixed.key"), &wrong)?;
    let edge = ApiServer::spawn(&[
        "--api-signing-key",
        KEY,
        "--node-name",
        "edge-a",
        "--hep-send",
        &hub.hep,
        "--hep-auth-mode",
        "hmac",
        "--hep-auth-file",
        wrong.to_str().ok_or("utf-8 path")?,
    ])?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let v = get_json(&hub.api, "/v1/inventory", &token)?;
        if v["hep_listener"]["senders"]
            .as_array()
            .is_some_and(|s| !s.is_empty())
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let edge_row = format!(
        "[[host]]\nname = \"edge-a\"\nurl = \"http://{}\"\ntoken_file = \"{tok}\"\n",
        edge.addr
    );
    std::fs::write(&hosts, format!("{hub_row}{edge_row}"))?;
    let (code, out, err) = fleet(&hosts, true)?;
    let report: serde_json::Value = serde_json::from_str(&out)?;
    let hub_now = &report["hosts"][0]["inventory"]["hep_listener"];
    assert!(
        hub_now["refused_sources"]
            .as_array()
            .is_some_and(|r| !r.is_empty()),
        "the collector still counts the old refusals: {report}"
    );
    assert_eq!(
        code, 0,
        "admitted after its last refusal, the sender is fixed: {out}\n{err}"
    );

    Ok(())
}

/// FLEET-P0.2: a secret held in a file is reported by its inode and
/// modification time under the setting that names it, so rotating the file
/// is visible across a restart, though the path, and with it every digest,
/// stays the same. Neither the key nor any digest of it is in the answer.
#[cfg(unix)]
#[test]
fn a_rotated_secret_file_shows_in_the_inventory() -> Result<(), TestError> {
    use std::os::unix::fs::MetadataExt as _;
    let dir = tempfile::tempdir()?;
    let key_path = dir.path().join("api.signing");
    let start = |key: &str| -> Result<(ApiServer, serde_json::Value), TestError> {
        let srv = ApiServer::spawn_unsettled(&[
            "--api-signing-key-file",
            key_path.to_str().ok_or("utf-8 path")?,
            "--node-name",
            "edge-r",
        ])?;
        let token = sipnab::auth::mint(
            key.as_bytes(),
            "fleet-e2e",
            chrono::Utc::now().timestamp() + 3600,
            sipnab::auth::AUDIENCE_API,
            sipnab::auth::SCOPE_INVENTORY,
        );
        let resp = srv.get_bearer("/v1/inventory", &token)?;
        assert_eq!(resp.status, 200, "{}", resp.body);
        let v = resp.json()?;
        Ok((srv, v))
    };
    let stamp_of = |v: &serde_json::Value| -> Result<serde_json::Value, TestError> {
        let rows = v["config"]["secret_files"]
            .as_array()
            .ok_or_else(|| format!("no secret_files: {v}"))?;
        let mine: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| r["setting"] == "--api-signing-key-file")
            .collect();
        assert_eq!(mine.len(), 1, "{v}");
        Ok(mine[0].clone())
    };

    const FIRST: &str = "fleet-rotation-first-signing-key-0123";
    const SECOND: &str = "fleet-rotation-second-signing-key-4567";
    token_file(dir.path(), "api.signing", FIRST)?;
    let meta = std::fs::metadata(&key_path)?;
    let (srv, before) = start(FIRST)?;
    let stamp = stamp_of(&before)?;
    assert_eq!(stamp["inode"], meta.ino(), "{stamp}");
    let mtime: chrono::DateTime<chrono::Utc> = meta.modified()?.into();
    assert_eq!(
        stamp["mtime"],
        mtime.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        "{stamp}"
    );
    drop(srv);

    // Rotate the usual way: a new file renamed over the old path.
    token_file(dir.path(), "api.signing.new", SECOND)?;
    std::fs::rename(dir.path().join("api.signing.new"), &key_path)?;
    let (_srv, after) = start(SECOND)?;
    let rotated = stamp_of(&after)?;
    assert_ne!(rotated["inode"], stamp["inode"], "{rotated} vs {stamp}");
    assert_eq!(
        rotated["inode"],
        std::fs::metadata(&key_path)?.ino(),
        "{rotated}"
    );
    assert_eq!(
        after["config"]["effective_sha256"], before["config"]["effective_sha256"],
        "the path did not change, so no digest does: only the stamp shows the rotation"
    );
    for (v, key) in [(&before, FIRST), (&after, SECOND)] {
        let body = v.to_string();
        assert!(!body.contains(key), "the key reached the answer: {body}");
        assert!(
            !body.contains(&sha256_hex(key.as_bytes())),
            "a digest of the key reached the answer: {body}"
        );
        assert!(
            !body.contains(&key_path.display().to_string()),
            "the path reached the answer: {body}"
        );
    }
    Ok(())
}

/// A fleet member's `fleet-report` token, minted with an instance's own
/// key, opens nothing on that instance's REST API: not the inventory, not
/// the dialogs, not the metrics. It is a credential for a fleet center's
/// ingest alone.
#[test]
fn a_fleet_report_token_opens_nothing_on_an_instance() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let (cfg, _) = config_file(dir.path(), "r.toml", "edge-r.cred")?;
    let srv = instance("edge-r", &cfg)?;
    let report = sipnab::auth::mint(
        KEY.as_bytes(),
        "edge-r",
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_FLEET_REPORT,
    );
    for path in ["/v1/inventory", "/v1/dialogs", "/v1/stats", "/metrics"] {
        let resp = srv.get_bearer(path, &report)?;
        assert_eq!(resp.status, 401, "{path}: {}", resp.body);
    }
    assert_eq!(
        srv.get_bearer("/v1/inventory", &inventory_token())?.status,
        200,
        "the route answers an inventory token, so the 401 is the scope's"
    );
    Ok(())
}

include!("support/child_lifetime.rs");
