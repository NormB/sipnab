// SPDX-License-Identifier: MIT OR Apache-2.0

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
    /// does not leave the process behind.
    pub(super) struct Running(pub(super) Option<std::process::Child>);

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(child) = self.0.take() {
                support::shutdown(child);
            }
        }
    }

    /// Start an HTTPS MCP server with `pki`'s files plus `extra`.
    fn spawn_tls(pki: &TestPki, extra: &[&str]) -> Result<(Running, String), TestError> {
        let mut args = vec!["--mcp-bind", "127.0.0.1:0"];
        args.extend(pki.args(CERT, KEY));
        args.extend_from_slice(extra);
        let (child, addr) = support::spawn_http(&args)?.ok_or("the HTTPS MCP server starts")?;
        Ok((Running(Some(child)), addr))
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
    /// client's handshake.
    #[test]
    fn mcp_a_silent_client_does_not_block_other_handshakes() -> Result<(), TestError> {
        let pki = test_pki("mcp-silent")?;
        let (child, addr) = spawn_tls(&pki, &[])?;
        let _silent = std::net::TcpStream::connect(&addr)?;
        let started = std::time::Instant::now();
        let init = initialize(&addr, &pki.ca, None)?;
        assert_eq!(init.status, 200);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "served after {:?}: the silent peer held the accept loop",
            started.elapsed()
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
    /// client's handshake.
    #[test]
    fn metrics_a_silent_client_does_not_block_other_handshakes() -> Result<(), TestError> {
        let pki = test_pki("metrics-silent")?;
        let run = spawn_tls(&pki, &[])?;
        let _silent = std::net::TcpStream::connect(&run.addr)?;
        let started = std::time::Instant::now();
        let (status, _) = https_get(&run.addr, "/metrics", &pki.ca, test_timeout(10))?;
        assert_eq!(status, 200);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "served after {:?}: the silent peer held the accept loop",
            started.elapsed()
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
        let child = super::mcp::Running(Some(child));
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
            (code, self.stdout.try_iter().collect())
        }
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
            collector.stdout.try_iter().next().is_none(),
            "the refused sender delivered nothing"
        );
        Ok(())
    }
}
