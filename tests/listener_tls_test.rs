// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

#![cfg(unix)]
//! TLS on the listeners that did not have it: MCP over HTTP
//! (`--mcp-tls-cert` / `--mcp-tls-key`) and the metrics endpoint
//! (`--metrics-tls-cert` / `--metrics-tls-key`).
//!
//! Each surface is held to what the REST API's TLS already promises, through
//! the real binary: a trusting client is served over HTTPS, plain HTTP and an
//! untrusting client are not, and every bad configuration stops the run at
//! startup with an error naming the flag or file at fault, before the port
//! is served.

#[cfg(any(feature = "mcp-http", feature = "metrics", feature = "hep"))]
#[path = "support/tls_pki.rs"]
mod tls_pki;

#[cfg(feature = "mcp-http")]
#[path = "support/mcp.rs"]
mod mcp_support;

#[cfg(feature = "metrics")]
#[path = "support/headless_metrics.rs"]
mod headless_metrics;

#[cfg(all(feature = "api", feature = "mcp-http", feature = "metrics"))]
#[path = "support/server.rs"]
mod api_server;

#[cfg(any(feature = "mcp-http", feature = "metrics", feature = "hep"))]
use std::io::Read;
#[cfg(any(feature = "mcp-http", feature = "metrics", feature = "hep"))]
use std::time::{Duration, Instant};

#[cfg(any(feature = "mcp-http", feature = "metrics", feature = "hep"))]
use tls_pki::TestError;

/// Run the binary with `args` until it exits or `wait` passes.
///
/// # Returns
///
/// `(stderr, exit code)`. The code is `None` when the run was still going at
/// the deadline (it is then killed), which is the failure a startup refusal
/// test is looking for.
#[cfg(any(feature = "mcp-http", feature = "metrics", feature = "hep"))]
fn run_until_exit(args: &[&str], wait: Duration) -> Result<(String, Option<i32>), TestError> {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .tied_to_test()
        .spawn()?;
    let mut stderr = child.stderr.take().ok_or("stderr is piped")?;
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    let by = Instant::now() + wait;
    let code = loop {
        if let Ok(Some(status)) = child.try_wait() {
            break status.code();
        }
        if Instant::now() >= by {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ok((reader.join().unwrap_or_default(), code))
}

/// Assert a run stopped at startup with a non-zero status and an error that
/// names every one of `needles`, and that it never reported `listening`.
#[cfg(any(feature = "mcp-http", feature = "metrics", feature = "hep"))]
fn assert_refused(args: &[&str], needles: &[&str], listening: &str) -> Result<(), TestError> {
    let (stderr, code) = run_until_exit(args, test_timeout(10))?;
    assert!(
        matches!(code, Some(c) if c != 0),
        "{args:?} must stop the run with a failure status, got {code:?}:\n{stderr}"
    );
    for needle in needles {
        assert!(
            stderr.contains(needle),
            "{args:?}: the error must name {needle}, got:\n{stderr}"
        );
    }
    assert!(
        !stderr.contains(listening),
        "{args:?} must not serve the port:\n{stderr}"
    );
    Ok(())
}

#[cfg(any(feature = "mcp-http", feature = "metrics", feature = "hep"))]
include!("support/timeout.rs");

/// MCP over HTTP with `--mcp-tls-cert` / `--mcp-tls-key`.
#[cfg(feature = "mcp-http")]
mod mcp {
    use super::TestError;
    use super::tls_pki::{HttpsResponse, TestPki, https_exchange, plain_http_get, test_pki};
    use super::{assert_refused, test_timeout};

    use super::mcp_support as support;

    const CERT: &str = "--mcp-tls-cert";
    const KEY: &str = "--mcp-tls-key";

    /// The base of a run serving MCP over HTTP from a capture file, bound to
    /// `bind`.
    fn base_on(fixture: &str, bind: &str) -> Vec<String> {
        [
            "-N",
            "-I",
            fixture,
            "--mcp",
            "--mcp-transport",
            "http",
            "--mcp-bind",
            bind,
            "--quiet",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    /// [`base_on`] bound to loopback.
    fn base(fixture: &str) -> Vec<String> {
        base_on(fixture, "127.0.0.1:0")
    }

    fn fixture() -> String {
        support::fixture("sip_call.pcap")
            .to_string_lossy()
            .into_owned()
    }

    /// A running MCP server, stopped when dropped, so a failing assertion
    /// does not leave the process behind. The rule is the shared harness's.
    use support::HttpServer as Running;

    /// Start an HTTPS MCP server with `pki`'s files plus `extra`.
    fn spawn_tls(pki: &TestPki, extra: &[&str]) -> Result<(Running, String), TestError> {
        let mut args = vec!["--mcp-bind", "127.0.0.1:0"];
        args.extend(pki.args(CERT, KEY));
        args.extend_from_slice(extra);
        let (child, addr) = support::spawn_http(&args)?.ok_or("the HTTPS MCP server starts")?;
        Ok((child, addr))
    }

    /// POST the JSON-RPC `initialize` over HTTPS.
    fn initialize(
        addr: &str,
        ca: &rustls::pki_types::CertificateDer<'static>,
        bearer: Option<&str>,
    ) -> Result<HttpsResponse, String> {
        let body = support::initialize_payload().to_string();
        let auth = bearer.map(|b| format!("Bearer {b}"));
        let mut headers = vec![
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
        ];
        if let Some(a) = auth.as_deref() {
            headers.push(("Authorization", a));
        }
        https_exchange(
            addr,
            "POST /mcp HTTP/1.1",
            &headers,
            body.as_bytes(),
            ca,
            test_timeout(10),
        )
    }

    /// With both flags MCP is served over HTTPS: a client trusting the
    /// issuing CA completes `initialize` and reads `/health`.
    #[test]
    fn mcp_tls_flags_serve_https() -> Result<(), TestError> {
        let pki = test_pki("mcp")?;
        let (child, addr) = spawn_tls(&pki, &[])?;
        let init = initialize(&addr, &pki.ca, None)?;
        assert_eq!(init.status, 200, "initialize over HTTPS: {}", init.body);
        let health = https_exchange(
            &addr,
            "GET /health HTTP/1.1",
            &[],
            &[],
            &pki.ca,
            test_timeout(10),
        )?;
        assert_eq!(health.status, 200);
        assert_eq!(health.body.trim(), "ok");
        drop(child);
        Ok(())
    }

    /// The bearer guard still applies over HTTPS: no token is 401, the right
    /// one is 200.
    #[test]
    fn mcp_tls_keeps_the_bearer_guard() -> Result<(), TestError> {
        let pki = test_pki("mcp-token")?;
        let (child, addr) = spawn_tls(&pki, &["--mcp-token", "tls-test-token"])?;
        let refused = initialize(&addr, &pki.ca, None)?;
        assert_eq!(refused.status, 401, "no token over HTTPS must be 401");
        let served = initialize(&addr, &pki.ca, Some("tls-test-token"))?;
        assert_eq!(served.status, 200, "the right token: {}", served.body);
        drop(child);
        Ok(())
    }

    /// A plain-HTTP request to the HTTPS port is not served.
    #[test]
    fn mcp_plain_http_to_the_tls_port_is_not_served() -> Result<(), TestError> {
        let pki = test_pki("mcp-plain")?;
        let (child, addr) = spawn_tls(&pki, &[])?;
        let text = plain_http_get(&addr, "/health", test_timeout(10))?;
        assert!(
            !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200"),
            "plain HTTP must not be answered on the TLS port: {text}"
        );
        drop(child);
        Ok(())
    }

    /// A client that does not trust the certificate fails the handshake, and
    /// the server goes on serving a client that does.
    #[test]
    fn mcp_an_untrusting_client_fails_the_handshake() -> Result<(), TestError> {
        let pki = test_pki("mcp-trust")?;
        let other = test_pki("mcp-other")?;
        let (child, addr) = spawn_tls(&pki, &[])?;
        let err = initialize(&addr, &other.ca, None)
            .err()
            .ok_or("a client trusting another CA must not complete the handshake")?;
        assert!(
            err.contains("certificate") || err.contains("UnknownIssuer"),
            "the failure must be the certificate check: {err}"
        );
        let init = initialize(&addr, &pki.ca, None)?;
        assert_eq!(init.status, 200);
        drop(child);
        Ok(())
    }

    /// A client that connects and never speaks does not hold up another
    /// client's handshake: the second client is served while the silent one
    /// is still connected. An inline handshake would close the silent
    /// connection at the 10 s handshake timeout before serving anyone else,
    /// so the open connection is the proof, not the elapsed time.
    #[test]
    fn mcp_a_silent_client_does_not_block_other_handshakes() -> Result<(), TestError> {
        let pki = test_pki("mcp-silent")?;
        let (child, addr) = spawn_tls(&pki, &[])?;
        let silent = std::net::TcpStream::connect(&addr)?;
        let init = initialize(&addr, &pki.ca, None)?;
        assert_eq!(init.status, 200);
        assert!(
            crate::tls_pki::server_still_holds(&silent)?,
            "the server closed the silent connection before it served the \
             second client: the silent peer held the accept loop"
        );
        drop(child);
        Ok(())
    }

    /// A non-loopback bind warns about plain HTTP, and does not once TLS is
    /// on. Both halves: without the first, a deleted warning would pass the
    /// second.
    #[test]
    fn mcp_the_non_loopback_warning_fires_only_without_tls() -> Result<(), TestError> {
        const WARNING: &str = "without TLS";
        let pki = test_pki("mcp-warn")?;
        let mut plain_args = base_on(&fixture(), "0.0.0.0:0");
        plain_args.extend(["--mcp-token", "t"].map(String::from));
        let plain_refs: Vec<&str> = plain_args.iter().map(String::as_str).collect();
        let (stderr, _) = super::run_until_exit(&plain_refs, test_timeout(3))?;
        assert!(
            stderr.contains(WARNING),
            "a plain non-loopback bind must warn:\n{stderr}"
        );
        let mut tls_args = plain_args.clone();
        tls_args.extend(pki.args(CERT, KEY).map(String::from));
        let tls_refs: Vec<&str> = tls_args.iter().map(String::as_str).collect();
        let (stderr, _) = super::run_until_exit(&tls_refs, test_timeout(3))?;
        assert!(
            stderr.contains("listening on"),
            "the TLS run must start:\n{stderr}"
        );
        assert!(
            !stderr.contains(WARNING),
            "a TLS bind must not warn about plain HTTP:\n{stderr}"
        );
        Ok(())
    }

    /// One flag without the other stops the run naming the file given and
    /// the flag missing, rather than serving plain HTTP on a port meant for
    /// HTTPS.
    #[test]
    fn mcp_one_tls_flag_alone_is_refused_naming_it() -> Result<(), TestError> {
        let pki = test_pki("mcp-alone")?;
        for (flag, file, missing) in [(CERT, &pki.cert, KEY), (KEY, &pki.key, CERT)] {
            let mut args = base(&fixture());
            args.extend([flag.to_string(), file.clone()]);
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            assert_refused(&refs, &[flag, file, missing], "listening on")?;
        }
        Ok(())
    }

    /// A missing certificate file stops the run naming it.
    #[test]
    fn mcp_a_missing_tls_file_is_refused_naming_it() -> Result<(), TestError> {
        let pki = test_pki("mcp-missing")?;
        let missing = pki.dir.path().join("no-such-cert.pem");
        let missing = missing.to_string_lossy().into_owned();
        let mut args = base(&fixture());
        args.extend([CERT, &missing, KEY, &pki.key].map(String::from));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_refused(&refs, &[&missing], "listening on")?;
        Ok(())
    }

    /// A key file the run cannot read stops it with exit 2 and a message
    /// naming the flag, the path and the operating system's reason. Before,
    /// it printed the bare path alone.
    #[test]
    fn mcp_an_unreadable_key_is_refused_naming_flag_path_and_reason() -> Result<(), TestError> {
        let pki = test_pki("mcp-unreadable-key")?;
        let missing = pki.dir.path().join("no-such-key.pem");
        let missing = missing.to_string_lossy().into_owned();
        let mut args = base(&fixture());
        args.extend([CERT, &pki.cert, KEY, &missing].map(String::from));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (stderr, code) = super::run_until_exit(&refs, test_timeout(10))?;
        assert_eq!(code, Some(2), "a refused flag exits 2:\n{stderr}");
        let want = format!("{KEY}: {missing}: No such file or directory");
        assert!(stderr.contains(&want), "want {want:?} in:\n{stderr}");
        Ok(())
    }

    /// A key any user on the host can read stops the run naming it.
    #[test]
    fn mcp_a_world_readable_key_is_refused_naming_it() -> Result<(), TestError> {
        let pki = test_pki("mcp-perm")?;
        pki.make_key_world_readable()?;
        let mut args = base(&fixture());
        args.extend(pki.args(CERT, KEY).map(String::from));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_refused(&refs, &[&pki.key, "world-readable"], "listening on")?;
        Ok(())
    }

    /// A key that is not the certificate's stops the run naming both files.
    #[test]
    fn mcp_a_key_that_is_not_the_certificates_is_refused() -> Result<(), TestError> {
        let pki = test_pki("mcp-pair")?;
        let other = test_pki("mcp-pair-other")?;
        let mut args = base(&fixture());
        args.extend([CERT, &pki.cert, KEY, &other.key].map(String::from));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_refused(&refs, &[&pki.cert, &other.key], "listening on")?;
        Ok(())
    }

    /// The flags belong to the HTTP transport. Given with the default stdio
    /// transport they would do nothing, so the run is refused naming the
    /// transport they need.
    #[test]
    fn mcp_tls_flags_without_the_http_transport_are_refused() -> Result<(), TestError> {
        let pki = test_pki("mcp-stdio")?;
        let fixture = fixture();
        let mut args = vec!["-N", "-I", &fixture, "--mcp", "--quiet"];
        args.extend(pki.args(CERT, KEY));
        assert_refused(&args, &[CERT, "--mcp-transport http"], "listening on")?;
        Ok(())
    }
}

/// The metrics endpoint with `--metrics-tls-cert` / `--metrics-tls-key`.
#[cfg(feature = "metrics")]
mod metrics {
    use super::TestError;
    use super::tls_pki::{TestPki, https_exchange, https_get, plain_http_get, test_pki};
    use super::{assert_refused, test_timeout};

    use super::headless_metrics as headless;

    const CERT: &str = "--metrics-tls-cert";
    const KEY: &str = "--metrics-tls-key";
    const LISTENING: &str = "Prometheus metrics server listening on";

    /// The base of a headless run serving metrics, kept alive by a HEP
    /// listener.
    fn base() -> Vec<String> {
        [
            "-N",
            "--hep-listen",
            "127.0.0.1:0",
            "--metrics",
            "127.0.0.1:0",
            "--quiet",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    fn spawn_tls(pki: &TestPki, extra: &[&str]) -> Result<Running, TestError> {
        let mut args: Vec<&str> = pki.args(CERT, KEY).to_vec();
        args.extend_from_slice(extra);
        Running::spawn(&args)
    }

    /// A running headless metrics server, stopped when dropped, so a failing
    /// assertion does not leave the process behind.
    pub(super) struct Running(headless::HeadlessMetrics);

    impl Running {
        pub(super) fn spawn(args: &[&str]) -> Result<Running, TestError> {
            Ok(Running(headless::HeadlessMetrics::spawn(
                std::path::Path::new(env!("CARGO_BIN_EXE_sipnab")),
                args,
                test_timeout(10),
            )?))
        }
    }

    impl std::ops::Deref for Running {
        type Target = headless::HeadlessMetrics;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.child.kill();
            let _ = self.0.child.wait();
        }
    }

    fn stop(run: Running) {
        drop(run);
    }

    /// With both flags `/metrics` is served over HTTPS to a client trusting
    /// the issuing CA, in the Prometheus text format.
    #[test]
    fn metrics_tls_flags_serve_https() -> Result<(), TestError> {
        let pki = test_pki("metrics")?;
        let run = spawn_tls(&pki, &[])?;
        let (status, body) = https_get(&run.addr, "/metrics", &pki.ca, test_timeout(10))?;
        assert_eq!(status, 200, "/metrics over HTTPS: {body}");
        assert!(
            body.contains("# TYPE sipnab_"),
            "the Prometheus text format: {body}"
        );
        stop(run);
        Ok(())
    }

    /// Basic auth still applies over HTTPS: no credential is 401, the right
    /// one is 200.
    #[test]
    fn metrics_tls_keeps_basic_auth() -> Result<(), TestError> {
        use base64::Engine as _;
        let pki = test_pki("metrics-auth")?;
        let run = spawn_tls(&pki, &["--metrics-auth", "scrape:s3cret"])?;
        let (status, _) = https_get(&run.addr, "/metrics", &pki.ca, test_timeout(10))?;
        assert_eq!(status, 401, "no credential over HTTPS must be 401");
        let credential = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("scrape:s3cret")
        );
        let served = https_exchange(
            &run.addr,
            "GET /metrics HTTP/1.1",
            &[("Authorization", &credential)],
            &[],
            &pki.ca,
            test_timeout(10),
        )?;
        assert_eq!(served.status, 200, "the right credential: {}", served.body);
        stop(run);
        Ok(())
    }

    /// A plain-HTTP request to the HTTPS port is not served.
    #[test]
    fn metrics_plain_http_to_the_tls_port_is_not_served() -> Result<(), TestError> {
        let pki = test_pki("metrics-plain")?;
        let run = spawn_tls(&pki, &[])?;
        let text = plain_http_get(&run.addr, "/metrics", test_timeout(10))?;
        assert!(
            !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200"),
            "plain HTTP must not be answered on the TLS port: {text}"
        );
        stop(run);
        Ok(())
    }

    /// A client that does not trust the certificate fails the handshake, and
    /// the server goes on serving a client that does.
    #[test]
    fn metrics_an_untrusting_client_fails_the_handshake() -> Result<(), TestError> {
        let pki = test_pki("metrics-trust")?;
        let other = test_pki("metrics-other")?;
        let run = spawn_tls(&pki, &[])?;
        let err = https_get(&run.addr, "/metrics", &other.ca, test_timeout(10))
            .err()
            .ok_or("a client trusting another CA must not complete the handshake")?;
        assert!(
            err.contains("certificate") || err.contains("UnknownIssuer"),
            "the failure must be the certificate check: {err}"
        );
        let (status, _) = https_get(&run.addr, "/metrics", &pki.ca, test_timeout(10))?;
        assert_eq!(status, 200);
        stop(run);
        Ok(())
    }

    /// A client that connects and never speaks does not hold up another
    /// client's handshake: the second client is served while the silent one
    /// is still connected. A handshake on the accept loop would close the
    /// silent connection at the 5 s connection timeout before serving anyone
    /// else, so the open connection is the proof, not the elapsed time.
    #[test]
    fn metrics_a_silent_client_does_not_block_other_handshakes() -> Result<(), TestError> {
        let pki = test_pki("metrics-silent")?;
        let run = spawn_tls(&pki, &[])?;
        let silent = std::net::TcpStream::connect(&run.addr)?;
        let (status, _) = https_get(&run.addr, "/metrics", &pki.ca, test_timeout(10))?;
        assert_eq!(status, 200);
        assert!(
            crate::tls_pki::server_still_holds(&silent)?,
            "the server closed the silent connection before it served the \
             second client: the silent peer held the accept loop"
        );
        stop(run);
        Ok(())
    }

    /// A non-loopback bind with Basic auth warns that the credential crosses
    /// the network unencrypted, and does not once TLS is on.
    #[test]
    fn metrics_the_plaintext_credential_warning_fires_only_without_tls() -> Result<(), TestError> {
        const WARNING: &str = "not encrypted";
        let pki = test_pki("metrics-warn")?;
        let wide: Vec<String> = [
            "-N",
            "--hep-listen",
            "127.0.0.1:0",
            "--metrics",
            "0.0.0.0:0",
            "--metrics-auth",
            "u:p",
            "--quiet",
        ]
        .map(String::from)
        .to_vec();
        let refs: Vec<&str> = wide.iter().map(String::as_str).collect();
        let (log, _) = super::run_until_exit(&refs, test_timeout(3))?;
        assert!(
            log.contains(LISTENING) && log.contains(WARNING),
            "a plain non-loopback bind must start and warn:\n{log}"
        );
        let mut args = refs.clone();
        args.extend(pki.args(CERT, KEY));
        let (log, _) = super::run_until_exit(&args, test_timeout(3))?;
        assert!(log.contains(LISTENING), "the HTTPS run must start:\n{log}");
        assert!(
            !log.contains(WARNING),
            "a TLS bind must not warn about an unencrypted credential:\n{log}"
        );
        Ok(())
    }

    /// One flag without the other stops the run naming the file given and
    /// the flag missing.
    #[test]
    fn metrics_one_tls_flag_alone_is_refused_naming_it() -> Result<(), TestError> {
        let pki = test_pki("metrics-alone")?;
        for (flag, file, missing) in [(CERT, &pki.cert, KEY), (KEY, &pki.key, CERT)] {
            let mut args = base();
            args.extend([flag.to_string(), file.clone()]);
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            assert_refused(&refs, &[flag, file, missing], LISTENING)?;
        }
        Ok(())
    }

    /// A missing certificate file stops the run naming it.
    #[test]
    fn metrics_a_missing_tls_file_is_refused_naming_it() -> Result<(), TestError> {
        let pki = test_pki("metrics-missing")?;
        let missing = pki.dir.path().join("no-such-cert.pem");
        let missing = missing.to_string_lossy().into_owned();
        let mut args = base();
        args.extend([CERT, &missing, KEY, &pki.key].map(String::from));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_refused(&refs, &[&missing], LISTENING)?;
        Ok(())
    }

    /// A key any user on the host can read stops the run naming it.
    #[test]
    fn metrics_a_world_readable_key_is_refused_naming_it() -> Result<(), TestError> {
        let pki = test_pki("metrics-perm")?;
        pki.make_key_world_readable()?;
        let mut args = base();
        args.extend(pki.args(CERT, KEY).map(String::from));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_refused(&refs, &[&pki.key, "world-readable"], LISTENING)?;
        Ok(())
    }

    /// A key that is not the certificate's stops the run naming both files.
    #[test]
    fn metrics_a_key_that_is_not_the_certificates_is_refused() -> Result<(), TestError> {
        let pki = test_pki("metrics-pair")?;
        let other = test_pki("metrics-pair-other")?;
        let mut args = base();
        args.extend([CERT, &pki.cert, KEY, &other.key].map(String::from));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_refused(&refs, &[&pki.cert, &other.key], LISTENING)?;
        Ok(())
    }

    /// The flags belong to `--metrics`. Without it they would do nothing, so
    /// the run is refused as a missing required argument. Matching the bare
    /// `--metrics` would prove nothing: it is part of the flag that was given,
    /// and clap's usage line names `--metrics <ADDR>` for any parse error.
    #[test]
    fn metrics_tls_flags_without_metrics_are_refused() -> Result<(), TestError> {
        let pki = test_pki("metrics-orphan")?;
        let mut args = vec!["-N", "--hep-listen", "127.0.0.1:0", "--quiet"];
        args.extend(pki.args(CERT, KEY));
        assert_refused(
            &args,
            &["required arguments were not provided", "--metrics <ADDR>"],
            LISTENING,
        )?;
        Ok(())
    }
}

/// The same listeners configured from `sipnab.toml` instead of flags:
/// `[api]`, `[mcp]` and `[metrics]` each take `tls_cert` and `tls_key`, and a
/// flag replaces its own key.
#[cfg(all(feature = "api", feature = "mcp-http", feature = "metrics"))]
mod config_keys {
    use super::TestError;
    use super::tls_pki::{TestPki, https_exchange, https_get, test_pki};
    use super::{assert_refused, mcp_support, test_timeout};

    use super::api_server as server;

    /// Write `body` as `sipnab.toml` beside `pki`'s files and return its path.
    fn config_file(pki: &TestPki, body: &str) -> Result<String, TestError> {
        let path = pki.dir.path().join("sipnab.toml");
        std::fs::write(&path, body)?;
        Ok(path.to_string_lossy().into_owned())
    }

    fn pair(section: &str, cert: &str, key: &str) -> String {
        format!("[{section}]\ntls_cert = \"{cert}\"\ntls_key = \"{key}\"\n")
    }

    /// `[api] tls_cert` / `tls_key` serve the REST API over HTTPS.
    #[test]
    fn the_api_keys_serve_https() -> Result<(), TestError> {
        let pki = test_pki("cfg-api")?;
        let cfg = config_file(&pki, &pair("api", &pki.cert, &pki.key))?;
        let srv = server::ApiServer::spawn_unsettled(&["--config", &cfg])?;
        let (status, body) = https_get(&srv.addr, "/health", &pki.ca, test_timeout(10))?;
        assert_eq!(status, 200, "{body}");
        Ok(())
    }

    /// `[mcp] tls_cert` / `tls_key` serve MCP over HTTPS.
    #[test]
    fn the_mcp_keys_serve_https() -> Result<(), TestError> {
        let pki = test_pki("cfg-mcp")?;
        let cfg = config_file(&pki, &pair("mcp", &pki.cert, &pki.key))?;
        let (child, addr) =
            mcp_support::spawn_http(&["--mcp-bind", "127.0.0.1:0", "--config", &cfg])?
                .ok_or("MCP starts")?;
        let resp = https_exchange(
            &addr,
            "GET /health HTTP/1.1",
            &[],
            &[],
            &pki.ca,
            test_timeout(10),
        )?;
        assert_eq!(resp.status, 200);
        drop(child);
        Ok(())
    }

    /// `[metrics] tls_cert` / `tls_key` serve the metrics endpoint over HTTPS.
    #[test]
    fn the_metrics_keys_serve_https() -> Result<(), TestError> {
        let pki = test_pki("cfg-metrics")?;
        let cfg = config_file(&pki, &pair("metrics", &pki.cert, &pki.key))?;
        let run = super::metrics::Running::spawn(&["--config", &cfg])?;
        let (status, body) = https_get(&run.addr, "/metrics", &pki.ca, test_timeout(10))?;
        assert_eq!(status, 200, "{body}");
        Ok(())
    }

    /// A flag replaces its own key: the file names a certificate that does
    /// not exist, the flag a good one, and the run serves HTTPS with the
    /// flag's certificate and the file's key.
    #[test]
    fn a_flag_replaces_its_own_key() -> Result<(), TestError> {
        let pki = test_pki("cfg-override")?;
        let missing = pki.dir.path().join("absent.pem");
        let cfg = config_file(&pki, &pair("metrics", &missing.to_string_lossy(), &pki.key))?;
        let run =
            super::metrics::Running::spawn(&["--config", &cfg, "--metrics-tls-cert", &pki.cert])?;
        let (status, _) = https_get(&run.addr, "/metrics", &pki.ca, test_timeout(10))?;
        assert_eq!(status, 200);
        Ok(())
    }

    /// A certificate key with no key from either source is refused, naming
    /// the key that was set and both ways to set the other.
    #[test]
    fn a_key_alone_is_refused_naming_both_sources_of_the_other() -> Result<(), TestError> {
        let pki = test_pki("cfg-alone")?;
        let cfg = config_file(&pki, &format!("[mcp]\ntls_cert = \"{}\"\n", pki.cert))?;
        let fixture = mcp_support::fixture("sip_call.pcap")
            .to_string_lossy()
            .into_owned();
        assert_refused(
            &[
                "-N",
                "-I",
                &fixture,
                "--mcp",
                "--mcp-transport",
                "http",
                "--mcp-bind",
                "127.0.0.1:0",
                "--config",
                &cfg,
            ],
            &[
                "[mcp] tls_cert",
                &pki.cert,
                "--mcp-tls-key",
                "[mcp] tls_key",
            ],
            "listening on",
        )?;
        Ok(())
    }
}

/// HEP over TLS configured from `sipnab.toml`: a collector whose certificate
/// and key come from `[hep] tls_cert` / `tls_key`, fed by a sender whose
/// trust comes from `[hep] tls_ca` or `[hep] tls_extra_ca`. Two real
/// processes, so the keys are proven to reach both ends of the wire.
#[cfg(feature = "hep")]
mod hep_keys {
    use super::TestError;
    use super::TiedToTest as _;
    use super::tls_pki::{TestPki, test_pki};
    use super::{run_until_exit, test_timeout};
    use std::io::{BufRead, BufReader};
    use std::time::{Duration, Instant};

    /// A collector `sipnab -N --hep-listen 127.0.0.1:0 --hep-listen-transport
    /// tls --count 1 --json`, configured by `cfg`.
    struct Collector {
        child: std::process::Child,
        port: u16,
        stdout: std::sync::mpsc::Receiver<String>,
    }

    impl Drop for Collector {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Collector {
        fn spawn(cfg: &str) -> Result<Collector, TestError> {
            let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
                .args([
                    "-N",
                    "--hep-listen",
                    "127.0.0.1:0",
                    "--hep-listen-transport",
                    "tls",
                    "--json",
                    "--count",
                    "1",
                    "--quiet",
                    "--config",
                    cfg,
                ])
                .env("SIPNAB_LOG", "info")
                .env("NO_COLOR", "1")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .tied_to_test()
                .spawn()?;
            let (out_tx, stdout) = std::sync::mpsc::channel();
            let out = child.stdout.take().ok_or("stdout")?;
            std::thread::spawn(move || {
                for line in BufReader::new(out).lines().map_while(Result::ok) {
                    let _ = out_tx.send(line);
                }
            });
            let (port_tx, port_rx) = std::sync::mpsc::channel();
            let err = child.stderr.take().ok_or("stderr")?;
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    if let Some(rest) = line.split("HEP listener started on ").nth(1)
                        && let Some(p) = rest.split_whitespace().next()
                        && let Some(p) = p.rsplit(':').next()
                        && let Ok(p) = p.parse::<u16>()
                    {
                        let _ = port_tx.send(p);
                    }
                }
            });
            let port = port_rx.recv_timeout(test_timeout(10))?;
            Ok(Collector {
                child,
                port,
                stdout,
            })
        }

        /// Wait for the `--count 1` run to end; its stdout lines.
        fn finish(mut self) -> (Option<i32>, Vec<String>) {
            let by = Instant::now() + test_timeout(15);
            let code = loop {
                if let Ok(Some(status)) = self.child.try_wait() {
                    break status.code();
                }
                if Instant::now() >= by {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            (
                code,
                drain_until_closed(&self.stdout, Instant::now() + test_timeout(5)),
            )
        }
    }

    /// Every line the reader thread forwards, up to the moment it closes.
    ///
    /// The lines arrive through a thread that reads the child's stdout, so
    /// the child's exit does not mean they are all in `rx`: the thread may
    /// still hold the last line. Taking what `rx` holds at that moment
    /// returned nothing on CI run 40667892510 although the collector had
    /// printed its packet. The thread drops its sender at EOF, so waiting for
    /// the disconnect is waiting for the whole of stdout; `by` bounds it for a
    /// pipe something else holds open.
    fn drain_until_closed(rx: &std::sync::mpsc::Receiver<String>, by: Instant) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            let left = by.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(line) => lines.push(line),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return lines,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    lines.extend(rx.try_iter());
                    return lines;
                }
            }
        }
    }

    /// A line the reader forwards after the child is gone is still collected.
    #[test]
    fn a_line_forwarded_after_the_exit_is_collected() -> Result<(), TestError> {
        let (tx, rx) = std::sync::mpsc::channel();
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let _ = tx.send("the packet".to_string());
        });
        let lines = drain_until_closed(&rx, Instant::now() + test_timeout(10));
        late.join().map_err(|_| "the late sender panicked")?;
        assert_eq!(lines, ["the packet"], "the late line is part of stdout");
        Ok(())
    }

    /// A reader that never closes does not hold the run past `by`.
    #[test]
    fn a_reader_that_never_closes_is_left_at_the_deadline() -> Result<(), TestError> {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let started = Instant::now();
        let lines = drain_until_closed(&rx, started + Duration::from_millis(300));
        assert!(lines.is_empty(), "nothing was sent: {lines:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the drain returned at its deadline, not later: {:?}",
            started.elapsed()
        );
        drop(tx);
        Ok(())
    }

    fn config_file(pki: &TestPki, name: &str, body: &str) -> Result<String, TestError> {
        let path = pki.dir.path().join(name);
        std::fs::write(&path, body)?;
        Ok(path.to_string_lossy().into_owned())
    }

    fn fixture() -> String {
        format!(
            "{}/tests/fixtures/sip_call.pcap",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    /// Send the fixture's SIP to `port` over TLS with the sender's config.
    fn send(port: u16, cfg: &str) -> Result<(String, Option<i32>), TestError> {
        let target = format!("127.0.0.1:{port}");
        let fixture = fixture();
        run_until_exit(
            &[
                "-N",
                "-I",
                &fixture,
                "--hep-send",
                &target,
                "--hep-send-transport",
                "tls",
                "--quiet",
                "--config",
                cfg,
            ],
            test_timeout(15),
        )
    }

    fn listener_config(pki: &TestPki) -> Result<String, TestError> {
        config_file(
            pki,
            "collector.toml",
            &format!(
                "[hep]\ntls_cert = \"{}\"\ntls_key = \"{}\"\n",
                pki.cert, pki.key
            ),
        )
    }

    /// `[hep] tls_ca` on the sender and `[hep] tls_cert` / `tls_key` on the
    /// collector carry a call over TLS.
    #[test]
    fn the_hep_keys_carry_a_tls_feed_with_a_named_ca() -> Result<(), TestError> {
        let pki = test_pki("hep-ca")?;
        let collector = Collector::spawn(&listener_config(&pki)?)?;
        let sender_cfg = config_file(
            &pki,
            "sender.toml",
            &format!("[hep]\ntls_ca = \"{}\"\n", pki.ca_file),
        )?;
        let (stderr, code) = send(collector.port, &sender_cfg)?;
        assert_eq!(code, Some(0), "the sender trusts the collector:\n{stderr}");
        let (code, stdout) = collector.finish();
        assert_eq!(code, Some(0), "the collector received its one packet");
        assert!(
            !stdout.is_empty(),
            "the collector reported what it received"
        );
        Ok(())
    }

    /// `[hep] tls_extra_ca` trusts the collector's private issuer beside the
    /// host's bundle. Without a host bundle the sender refuses instead, and
    /// that refusal is asserted.
    #[test]
    fn the_hep_keys_carry_a_tls_feed_with_an_extra_ca() -> Result<(), TestError> {
        let pki = test_pki("hep-extra")?;
        let collector = Collector::spawn(&listener_config(&pki)?)?;
        let sender_cfg = config_file(
            &pki,
            "sender.toml",
            &format!("[hep]\ntls_extra_ca = \"{}\"\n", pki.ca_file),
        )?;
        let (stderr, code) = send(collector.port, &sender_cfg)?;
        let host_bundle = std::env::var_os("SSL_CERT_FILE").is_some()
            || [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
                "/etc/ssl/cert.pem",
                "/opt/homebrew/etc/openssl@3/cert.pem",
            ]
            .iter()
            .any(|p| std::path::Path::new(p).is_file());
        if host_bundle {
            assert_eq!(
                code,
                Some(0),
                "the extra CA issued the collector's certificate:\n{stderr}"
            );
            let (code, _) = collector.finish();
            assert_eq!(code, Some(0), "the collector received its one packet");
        } else {
            assert!(
                stderr.contains("--hep-tls-ca"),
                "no host bundle: the refusal names the replace option:\n{stderr}"
            );
        }
        Ok(())
    }

    /// A TLS collector with no certificate from either source stops the run
    /// at startup, naming both the flags and the keys that would supply it.
    #[test]
    fn a_tls_collector_with_no_certificate_is_refused_at_startup() -> Result<(), TestError> {
        super::assert_refused(
            &[
                "-N",
                "--hep-listen",
                "127.0.0.1:0",
                "--hep-listen-transport",
                "tls",
                "--no-config",
            ],
            &[
                "--hep-tls-cert",
                "[hep] tls_cert",
                "--hep-tls-key",
                "[hep] tls_key",
            ],
            "HEP listener started on",
        )?;
        Ok(())
    }

    /// The negative control: with no trust configured, the host's bundle
    /// alone does not hold the test CA, so the sender refuses the collector.
    /// Without this, the two tests above would pass for a sender that trusts
    /// everything.
    #[test]
    fn without_the_trust_keys_the_collector_is_refused() -> Result<(), TestError> {
        let pki = test_pki("hep-none")?;
        let collector = Collector::spawn(&listener_config(&pki)?)?;
        let sender_cfg = config_file(&pki, "sender.toml", "")?;
        let (stderr, code) = send(collector.port, &sender_cfg)?;
        assert_eq!(
            code,
            Some(2),
            "a collector from an untrusted issuer must fail the run:\n{stderr}"
        );
        assert!(
            stderr.contains("Failed to establish a TLS session"),
            "the refusal names the handshake:\n{stderr}"
        );
        let mut collector = collector;
        let _ = collector.child.kill();
        let _ = collector.child.wait();
        assert!(
            drain_until_closed(&collector.stdout, Instant::now() + test_timeout(5)).is_empty(),
            "the refused sender delivered nothing"
        );
        Ok(())
    }
}

/// Client certificates (mutual TLS) on the REST API and MCP over HTTP,
/// through the real binary: `--api-tls-client-ca` / `--api-tls-client-auth`
/// and the MCP pair.
///
/// Each refusal is a fault the test injects on purpose: no certificate,
/// another CA's, an expired one, one not yet valid, one made for a server.
/// Each must stop the handshake, the server must log why, and the listener
/// must go on serving a client whose certificate is good. The certificates
/// come from a CA made for the test (`tls_pki::client_ca`).
#[cfg(all(feature = "api", feature = "mcp-http", feature = "metrics"))]
mod client_certs {
    use super::TestError;
    use super::tls_pki::{
        ClientCert, HttpsResponse, TestPki, Validity, client_ca, https_exchange_as, test_pki,
    };
    use super::{assert_refused, mcp_support, test_timeout};

    use super::api_server as server;

    /// The REST API's bearer token in these tests.
    const TOKEN: &str = "mtls-test-token";

    /// `GET /v1/stats` over HTTPS presenting `client`, with the bearer token
    /// when `bearer` is set.
    fn stats(
        srv: &server::ApiServer,
        pki: &TestPki,
        client: Option<&ClientCert>,
        bearer: bool,
    ) -> Result<HttpsResponse, String> {
        let auth = format!("Bearer {TOKEN}");
        let headers: Vec<(&str, &str)> = if bearer {
            vec![("Authorization", auth.as_str())]
        } else {
            Vec::new()
        };
        https_exchange_as(
            &srv.addr,
            "GET /v1/stats HTTP/1.1",
            &headers,
            &[],
            &pki.ca,
            client,
            test_timeout(10),
        )
    }

    /// Start the REST API over HTTPS with a token, asking for client
    /// certificates from `ca_file` with `extra` flags.
    fn spawn_api(
        pki: &TestPki,
        ca_file: &str,
        extra: &[&str],
    ) -> Result<server::ApiServer, TestError> {
        let mut args = vec!["--api-key", TOKEN, "--api-tls-client-ca", ca_file];
        args.extend(pki.args("--api-tls-cert", "--api-tls-key"));
        args.extend_from_slice(extra);
        server::ApiServer::spawn_unsettled(&args)
    }

    /// The server's log line for a refused client certificate, or a failure
    /// naming what was expected.
    fn refusal_logged(srv: &server::ApiServer, why: &str) -> Result<String, TestError> {
        srv.wait_for_log("refused the TLS handshake", test_timeout(10))
            .filter(|line| line.contains(why))
            .ok_or_else(|| format!("the server must log the refusal naming {why:?}").into())
    }

    /// A REST API with a client CA (and no mode, so `required`) refuses a
    /// handshake without a certificate, logs why, and serves a client whose
    /// certificate the CA issued, naming it in the log.
    #[test]
    fn the_api_refuses_a_client_without_a_certificate() -> Result<(), TestError> {
        let pki = test_pki("mtls-api")?;
        let ca = client_ca("mtls-api")?;
        let srv = spawn_api(&pki, &ca.ca_file, &[])?;
        assert!(
            srv.startup_log
                .contains("API TLS asks clients for a certificate (required)"),
            "{}",
            srv.startup_log
        );
        let refused = stats(&srv, &pki, None, true);
        assert!(
            refused.is_err(),
            "no certificate must be refused: {refused:?}"
        );
        let line = refusal_logged(&srv, "client certificate: peer sent no certificates")?;
        assert!(line.contains("WARN"), "a refusal is a warning: {line}");

        let member = ca.issue("member-1", Validity::Current)?;
        let served = stats(&srv, &pki, Some(&member), true)?;
        assert_eq!(served.status, 200, "{}", served.body);
        let named = srv
            .wait_for_log("presented a verified client certificate", test_timeout(10))
            .ok_or("the verified client is logged")?;
        assert!(
            named.contains(
                "subject=\"O=sipnab test fleet,CN=member-1\" \
                 dns=[\"member-1.fleet.example.com\"] \
                 uri=[\"spiffe://fleet.example.com/member/member-1\"]"
            ),
            "{named}"
        );
        Ok(())
    }

    /// The certificate does not replace the token: a good certificate
    /// without the bearer token is still 401.
    #[test]
    fn the_api_still_needs_the_token_with_a_certificate() -> Result<(), TestError> {
        let pki = test_pki("mtls-and")?;
        let ca = client_ca("mtls-and")?;
        let srv = spawn_api(&pki, &ca.ca_file, &[])?;
        let member = ca.issue("member-2", Validity::Current)?;
        let refused = stats(&srv, &pki, Some(&member), false)?;
        assert_eq!(refused.status, 401, "{}", refused.body);
        Ok(())
    }

    /// Another CA's certificate, an expired one, one not yet valid and one
    /// made for a server are each refused and logged; the listener still
    /// serves a good one afterwards.
    #[test]
    fn the_api_refuses_each_bad_certificate() -> Result<(), TestError> {
        let pki = test_pki("mtls-bad")?;
        let ca = client_ca("mtls-bad")?;
        let srv = spawn_api(&pki, &ca.ca_file, &[])?;
        let cases = [
            (
                client_ca("mtls-stranger")?.issue("intruder", Validity::Current)?,
                "invalid peer certificate: UnknownIssuer",
            ),
            (
                ca.issue("member-3", Validity::Expired)?,
                "invalid peer certificate: certificate expired",
            ),
            (
                ca.issue("member-4", Validity::NotYetValid)?,
                "invalid peer certificate: certificate not valid yet",
            ),
            (
                ca.issue_server_only("member-5")?,
                "invalid peer certificate: certificate does not allow extended key usage",
            ),
        ];
        for (cert, why) in &cases {
            let refused = stats(&srv, &pki, Some(cert), true);
            assert!(refused.is_err(), "{why}: must be refused, got {refused:?}");
            refusal_logged(&srv, why)?;
        }
        let good = ca.issue("member-6", Validity::Current)?;
        assert_eq!(
            stats(&srv, &pki, Some(&good), true)?.status,
            200,
            "a good certificate is served after the refusals"
        );
        Ok(())
    }

    /// `optional` serves a client without a certificate and still refuses
    /// one with a bad certificate.
    #[test]
    fn the_api_optional_mode_admits_no_certificate_but_not_a_bad_one() -> Result<(), TestError> {
        let pki = test_pki("mtls-opt")?;
        let ca = client_ca("mtls-opt")?;
        let srv = spawn_api(&pki, &ca.ca_file, &["--api-tls-client-auth", "optional"])?;
        assert_eq!(
            stats(&srv, &pki, None, true)?.status,
            200,
            "optional serves a client with no certificate"
        );
        let stranger = client_ca("mtls-opt-other")?.issue("intruder", Validity::Current)?;
        assert!(
            stats(&srv, &pki, Some(&stranger), true).is_err(),
            "optional still refuses another CA's certificate"
        );
        Ok(())
    }

    /// `[api] tls_client_ca` and `tls_client_auth` configure the same.
    #[test]
    fn the_api_config_keys_ask_for_a_certificate() -> Result<(), TestError> {
        let pki = test_pki("mtls-cfg")?;
        let ca = client_ca("mtls-cfg")?;
        let cfg = pki.dir.path().join("sipnab.toml");
        std::fs::write(
            &cfg,
            format!(
                "[api]\ntls_cert = \"{}\"\ntls_key = \"{}\"\ntls_client_ca = \"{}\"\n\
                 tls_client_auth = \"required\"\n",
                pki.cert, pki.key, ca.ca_file
            ),
        )?;
        let cfg = cfg.to_string_lossy().into_owned();
        let srv = server::ApiServer::spawn_unsettled(&["--api-key", TOKEN, "--config", &cfg])?;
        assert!(
            stats(&srv, &pki, None, true).is_err(),
            "the config keys refuse a client with no certificate"
        );
        let member = ca.issue("member-7", Validity::Current)?;
        assert_eq!(
            stats(&srv, &pki, Some(&member), true)?.status,
            200,
            "the config keys serve the client CA's certificate"
        );
        Ok(())
    }

    /// Settings that cannot be served stop the run at startup, naming the
    /// flags, before the port is served.
    #[test]
    fn contradictory_client_settings_stop_the_run() -> Result<(), TestError> {
        let pki = test_pki("mtls-refuse")?;
        let ca = client_ca("mtls-refuse")?;
        let fixture = format!(
            "{}/tests/fixtures/sip_call.pcap",
            env!("CARGO_MANIFEST_DIR")
        );
        let base = [
            "-N",
            "-I",
            fixture.as_str(),
            "--api",
            "127.0.0.1:0",
            "--quiet",
        ];
        let tls = pki.args("--api-tls-cert", "--api-tls-key");
        let listening = "REST API listening on";
        let with = |extra: &[&str], tls_too: bool| -> Vec<String> {
            let mut v: Vec<&str> = base.to_vec();
            if tls_too {
                v.extend(tls);
            }
            v.extend_from_slice(extra);
            v.into_iter().map(String::from).collect()
        };
        let cases: [(Vec<String>, &[&str]); 2] = [
            (
                with(&["--api-tls-client-ca", &ca.ca_file], false),
                &[
                    "--api-tls-client-ca (or [api] tls_client_ca)",
                    "needs --api-tls-cert (or [api] tls_cert)",
                ],
            ),
            (
                with(&["--api-tls-client-auth", "required"], true),
                &[
                    "--api-tls-client-auth (or [api] tls_client_auth) required needs --api-tls-client-ca (or [api] tls_client_ca)",
                ],
            ),
        ];
        for (args, needles) in &cases {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            assert_refused(&refs, needles, listening)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ca.ca_file, std::fs::Permissions::from_mode(0o666))?;
            let args = with(&["--api-tls-client-ca", &ca.ca_file], true);
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            assert_refused(
                &refs,
                &["client CA file is writable by every user"],
                listening,
            )?;
        }
        Ok(())
    }

    /// `--api-tls-client-auth off` wins over a client CA from the config
    /// file: the API asks for no certificate, serves a client without one,
    /// and says at startup that it does not read the CA.
    #[test]
    fn the_api_off_mode_overrides_a_client_ca_from_the_config() -> Result<(), TestError> {
        let pki = test_pki("mtls-off")?;
        let ca = client_ca("mtls-off")?;
        let cfg = pki.dir.path().join("sipnab.toml");
        std::fs::write(&cfg, format!("[api]\ntls_client_ca = \"{}\"\n", ca.ca_file))?;
        let cfg = cfg.to_string_lossy().into_owned();
        let srv = spawn_api(
            &pki,
            &ca.ca_file,
            &["--config", &cfg, "--api-tls-client-auth", "off"],
        )?;
        let notice = format!(
            "API TLS asks clients for no certificate: the client-auth mode is off, so the \
             client CA {} is not read",
            ca.ca_file
        );
        assert!(srv.startup_log.contains(&notice), "{}", srv.startup_log);
        let served = stats(&srv, &pki, None, true)?;
        assert_eq!(
            served.status, 200,
            "off serves a client with no certificate"
        );
        Ok(())
    }

    /// A running MCP server, stopped when dropped.
    use mcp_support::HttpServer as Mcp;

    /// POST one JSON-RPC message to MCP over HTTPS, presenting `client`,
    /// inside `session` when given.
    fn mcp_post(
        addr: &str,
        pki: &TestPki,
        client: Option<&ClientCert>,
        session: Option<&str>,
        body: &serde_json::Value,
    ) -> Result<HttpsResponse, String> {
        let mut headers = vec![
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
        ];
        if let Some(id) = session {
            headers.push(("Mcp-Session-Id", id));
        }
        https_exchange_as(
            addr,
            "POST /mcp HTTP/1.1",
            &headers,
            body.to_string().as_bytes(),
            &pki.ca,
            client,
            test_timeout(10),
        )
    }

    /// MCP over HTTP with a client CA refuses a handshake without a
    /// certificate, serves one with, and its audit record names the client
    /// by the certificate's URI.
    #[test]
    fn mcp_refuses_no_certificate_and_audits_the_verified_client() -> Result<(), TestError> {
        let pki = test_pki("mtls-mcp")?;
        let ca = client_ca("mtls-mcp")?;
        let audit = pki.dir.path().join("audit.jsonl");
        let audit_arg = audit.to_string_lossy().into_owned();
        let mut args = vec![
            "--mcp-bind",
            "127.0.0.1:0",
            "--mcp-tls-client-ca",
            &ca.ca_file,
        ];
        args.extend(pki.args("--mcp-tls-cert", "--mcp-tls-key"));
        args.extend(["--mcp-audit-file", &audit_arg]);
        let (child, addr) = mcp_support::spawn_http(&args)?.ok_or("MCP starts")?;
        let _running = child;

        let init = mcp_support::initialize_payload();
        let refused = mcp_post(&addr, &pki, None, None, &init);
        assert!(
            refused.is_err(),
            "no certificate must be refused: {refused:?}"
        );

        let member = ca.issue("member-8", Validity::Current)?;
        let reply = mcp_post(&addr, &pki, Some(&member), None, &init)?;
        assert_eq!(reply.status, 200, "{}", reply.body);
        let session = reply
            .head
            .lines()
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.trim().eq_ignore_ascii_case("mcp-session-id"))
                    .map(|(_, v)| v.trim().to_string())
            })
            .ok_or("initialize returns a session")?;
        let note = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        mcp_post(&addr, &pki, Some(&member), Some(&session), &note)?;
        let call = serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "server_capabilities", "arguments": {}}
        });
        let answer = mcp_post(&addr, &pki, Some(&member), Some(&session), &call)?;
        assert_eq!(answer.status, 200, "{}", answer.body);

        let deadline = std::time::Instant::now() + test_timeout(10);
        let record = loop {
            let text = std::fs::read_to_string(&audit).unwrap_or_default();
            if let Some(line) = text.lines().find(|l| l.contains("server_capabilities")) {
                break line.to_string();
            }
            if std::time::Instant::now() > deadline {
                return Err(format!("no audit record for the call: {text}").into());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let record: serde_json::Value = serde_json::from_str(&record)?;
        let caller = record["caller"].as_str().unwrap_or_default();
        assert!(
            caller.ends_with(" client-cert=spiffe:%2F%2Ffleet.example.com%2Fmember%2Fmember-8"),
            "{caller}"
        );
        Ok(())
    }

    /// The MCP client-certificate flags belong to the HTTP transport. With
    /// stdio they would do nothing, so the run is refused naming the
    /// transport they need.
    #[test]
    fn mcp_client_flags_without_the_http_transport_are_refused() -> Result<(), TestError> {
        let fixture = format!(
            "{}/tests/fixtures/sip_call.pcap",
            env!("CARGO_MANIFEST_DIR")
        );
        let args = [
            "-N",
            "-I",
            fixture.as_str(),
            "--mcp",
            "--quiet",
            "--mcp-tls-client-auth",
            "off",
        ];
        assert_refused(
            &args,
            &[
                "--mcp-tls-client-ca/--mcp-tls-client-auth ask MCP over HTTPS clients for a \
                 certificate and do nothing without --mcp --mcp-transport http",
            ],
            "listening on",
        )
    }

    /// Start MCP over HTTPS asking for client certificates from `ca_file`,
    /// with `extra` flags.
    fn spawn_mcp(pki: &TestPki, ca_file: &str, extra: &[&str]) -> Result<(Mcp, String), TestError> {
        let mut args = vec!["--mcp-bind", "127.0.0.1:0", "--mcp-tls-client-ca", ca_file];
        args.extend(pki.args("--mcp-tls-cert", "--mcp-tls-key"));
        args.extend_from_slice(extra);
        let (child, addr) = mcp_support::spawn_http(&args)?.ok_or("MCP starts")?;
        Ok((child, addr))
    }

    /// MCP refuses another CA's certificate and an expired one.
    #[test]
    fn mcp_refuses_another_cas_and_an_expired_certificate() -> Result<(), TestError> {
        let pki = test_pki("mtls-mcp-bad")?;
        let ca = client_ca("mtls-mcp-bad")?;
        let (_mcp, addr) = spawn_mcp(&pki, &ca.ca_file, &[])?;
        let init = mcp_support::initialize_payload();
        let stranger = client_ca("mtls-mcp-other")?.issue("intruder", Validity::Current)?;
        let expired = ca.issue("member-old", Validity::Expired)?;
        for (cert, what) in [(&stranger, "another CA's"), (&expired, "an expired")] {
            let answer = mcp_post(&addr, &pki, Some(cert), None, &init);
            assert!(
                answer.is_err(),
                "{what} certificate must be refused: {answer:?}"
            );
        }
        Ok(())
    }

    /// MCP with `optional` serves an agent that sends no certificate.
    #[test]
    fn mcp_optional_mode_serves_an_agent_without_a_certificate() -> Result<(), TestError> {
        let pki = test_pki("mtls-mcp-opt")?;
        let ca = client_ca("mtls-mcp-opt")?;
        let (_mcp, addr) = spawn_mcp(&pki, &ca.ca_file, &["--mcp-tls-client-auth", "optional"])?;
        let reply = mcp_post(&addr, &pki, None, None, &mcp_support::initialize_payload())?;
        assert_eq!(
            reply.status, 200,
            "optional serves no certificate: {}",
            reply.body
        );
        Ok(())
    }

    /// `[mcp] tls_client_ca` asks MCP clients for a certificate as the flag
    /// does.
    #[test]
    fn mcp_config_key_asks_for_a_certificate() -> Result<(), TestError> {
        let pki = test_pki("mtls-mcp-cfg")?;
        let ca = client_ca("mtls-mcp-cfg")?;
        let cfg = pki.dir.path().join("sipnab.toml");
        std::fs::write(
            &cfg,
            format!(
                "[mcp]\ntls_cert = \"{}\"\ntls_key = \"{}\"\ntls_client_ca = \"{}\"\n",
                pki.cert, pki.key, ca.ca_file
            ),
        )?;
        let cfg = cfg.to_string_lossy().into_owned();
        let (child, addr) =
            mcp_support::spawn_http(&["--mcp-bind", "127.0.0.1:0", "--config", &cfg])?
                .ok_or("MCP starts")?;
        let _mcp = child;
        let init = mcp_support::initialize_payload();
        assert!(
            mcp_post(&addr, &pki, None, None, &init).is_err(),
            "the key asks for a certificate, so none is refused"
        );
        let member = ca.issue("member-cfg", Validity::Current)?;
        let reply = mcp_post(&addr, &pki, Some(&member), None, &init)?;
        assert_eq!(
            reply.status, 200,
            "a certificate from the key's CA: {}",
            reply.body
        );
        Ok(())
    }

    /// MCP's settings stop the run as the REST API's do.
    #[test]
    fn mcp_contradictory_client_settings_stop_the_run() -> Result<(), TestError> {
        let fixture = format!(
            "{}/tests/fixtures/sip_call.pcap",
            env!("CARGO_MANIFEST_DIR")
        );
        let args = [
            "-N",
            "-I",
            fixture.as_str(),
            "--mcp",
            "--mcp-transport",
            "http",
            "--mcp-bind",
            "127.0.0.1:0",
            "--quiet",
            "--mcp-tls-client-auth",
            "optional",
        ];
        assert_refused(
            &args,
            &[
                "--mcp-tls-client-auth (or [mcp] tls_client_auth) optional needs --mcp-tls-client-ca (or [mcp] tls_client_ca)",
            ],
            "listening on",
        )
    }
}

include!("support/child_lifetime.rs");
