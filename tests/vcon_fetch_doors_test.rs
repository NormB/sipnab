// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `GET /v1/vcon/fetch/{uuid}`, driven through the `sipnab` binary against a
//! fake vCon store.
//!
//! The store is a `std::net::TcpListener` on `127.0.0.1` that this file runs
//! itself, as `vcon_fetch_test.rs` does; no test contacts the internet. The
//! in-crate tests in `src/app/vcon_fetch.rs` cover every answer of the shared
//! function; this file proves the opt-in flag and the `[vcon_fetch]` keys
//! reach the route in a real run.

#![cfg(all(feature = "api", feature = "vcon", unix))]

#[path = "support/server.rs"]
mod server;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// Any error, boxed, so `?` works on every error type alike.
type TestError = Box<dyn std::error::Error>;

/// The uuid the store holds. Synthetic.
const UUID: &str = "018bcfe5-6800-8a6b-a667-78f1c5213800";

/// A synthetic unsigned container. Not anyone's call.
fn container() -> String {
    format!(
        r#"{{"vcon":"0.4.0","uuid":"{UUID}","created_at":"2026-10-07T12:00:00+00:00","parties":[{{"tel":"+15550100001"}}],"dialog":[],"attachments":[],"analysis":[]}}"#
    )
}

/// A conserver-shaped store that answers `GET /vcon/<UUID>` with
/// [`container`] and anything else with `404`, counting requests. It stops
/// when dropped.
struct Store {
    url: String,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Drop for Store {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn store() -> Result<Store, TestError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = format!("http://{}", listener.local_addr()?);
    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (count, halt) = (Arc::clone(&hits), Arc::clone(&stop));
    std::thread::spawn(move || {
        while !halt.load(Ordering::SeqCst) {
            let Ok((mut sock, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            let _ = sock.set_nonblocking(false);
            let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match sock.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            count.fetch_add(1, Ordering::SeqCst);
            let line = String::from_utf8_lossy(&head);
            let (status, body) = if line.starts_with(&format!("GET /vcon/{UUID} ")) {
                (200, container())
            } else {
                (404, "{}".to_string())
            };
            let answer = format!(
                "HTTP/1.1 {status} Scripted\r\nContent-Length: {}\r\n\
                 Content-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(answer.as_bytes());
        }
    });
    Ok(Store { url, hits, stop })
}

/// A config file naming `store` as the `[vcon_fetch]` conserver, with its
/// credential in a file only its owner reads.
fn config(dir: &Path, store: &Store) -> Result<PathBuf, TestError> {
    use std::os::unix::fs::PermissionsExt;
    let key = dir.join("store.key");
    std::fs::write(&key, format!("vcf_test_{}\n", "91c4e07a2b3d"))?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    let toml = dir.join("sipnab.toml");
    std::fs::write(
        &toml,
        format!(
            "[vcon_fetch]\nkind = \"conserver\"\nurl = \"{}\"\nauth_file = {:?}\n",
            store.url,
            key.display().to_string()
        ),
    )?;
    Ok(toml)
}

/// With `--api-allow-vcon-fetch` and a `[vcon_fetch]` store, the route
/// returns the stored container inline; a uuid the store does not hold is a
/// 404.
#[test]
fn the_route_returns_the_stored_container_with_the_opt_in() -> Result<(), TestError> {
    let store = store()?;
    let dir = tempfile::tempdir()?;
    let toml = config(dir.path(), &store)?;
    let srv = server::ApiServer::spawn(&[
        "--config",
        toml.to_str().ok_or("utf-8 path")?,
        "--api-allow-vcon-fetch",
    ])?;
    let resp = srv.get(&format!("/v1/vcon/fetch/{UUID}"))?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    let v = resp.json()?;
    assert_eq!(v["stored_form"], "unsigned", "{v}");
    assert_eq!(v["decrypted"], false, "{v}");
    let want: serde_json::Value = serde_json::from_str(&container())?;
    assert_eq!(v["container"], want, "{v}");

    let missing = srv.get("/v1/vcon/fetch/00000000-0000-0000-0000-000000000000")?;
    assert_eq!(missing.status, 404, "{}", missing.body);
    assert_eq!(store.hits.load(Ordering::SeqCst), 2);
    Ok(())
}

/// The same store without the flag: the route answers 503 naming the flag,
/// and the store hears nothing.
#[test]
fn the_route_is_refused_without_the_opt_in() -> Result<(), TestError> {
    let store = store()?;
    let dir = tempfile::tempdir()?;
    let toml = config(dir.path(), &store)?;
    let srv = server::ApiServer::spawn(&["--config", toml.to_str().ok_or("utf-8 path")?])?;
    let resp = srv.get(&format!("/v1/vcon/fetch/{UUID}"))?;
    assert_eq!(resp.status, 503, "{}", resp.body);
    assert!(
        resp.body.contains("--api-allow-vcon-fetch"),
        "{}",
        resp.body
    );
    assert_eq!(store.hits.load(Ordering::SeqCst), 0);
    Ok(())
}
