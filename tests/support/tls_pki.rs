// SPDX-License-Identifier: MIT OR Apache-2.0

//! A private certificate authority, a server certificate it issued for
//! `127.0.0.1`, and a client that trusts only that authority.
//!
//! Shared by every test of a listener that serves TLS itself: the REST API
//! (`--api-tls-cert`), MCP over HTTP (`--mcp-tls-cert`) and the metrics
//! endpoint (`--metrics-tls-cert`). One copy, so the three surfaces are
//! tested against the same certificates and the same client.
//!
//! A CA plus a leaf rather than one self-signed certificate: webpki, which
//! the rustls client verifies with, does not accept an end-entity
//! certificate as its own trust anchor, and a leaf issued by a private CA is
//! also what an operator hands sipnab in practice.
//!
//! Included with `#[path]`; `#![allow(dead_code)]` because each consumer uses
//! only part of it.
#![allow(dead_code)]

use std::io::{Read, Write};

/// The error a fallible helper here returns: any error, boxed, so `?` works
/// on I/O and certificate errors alike.
pub type TestError = Box<dyn std::error::Error>;

/// A CA and a server certificate it issued, written as PEM files into a
/// temporary directory.
pub struct TestPki {
    /// Holds the files; removed on drop.
    pub dir: tempfile::TempDir,
    /// The server certificate chain (PEM).
    pub cert: String,
    /// The server's private key (PEM), mode 0600.
    pub key: String,
    /// The CA certificate (PEM file), for a trust-store flag.
    pub ca_file: String,
    /// The CA a client must trust to accept `cert`.
    pub ca: rustls::pki_types::CertificateDer<'static>,
}

/// Issue a fresh [`TestPki`] whose files are named `<stem>.pem`,
/// `<stem>.key` and `<stem>-ca.pem`.
pub fn test_pki(stem: &str) -> Result<TestPki, TestError> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType,
    };
    let dir = tempfile::tempdir()?;
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, format!("sipnab {stem} test CA"));
    let ca_cert = ca_params.clone().self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, &ca_key);

    let leaf_key = KeyPair::generate()?;
    let mut leaf = CertificateParams::default();
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.subject_alt_names = vec![SanType::IpAddress(std::net::IpAddr::V4(
        std::net::Ipv4Addr::LOCALHOST,
    ))];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.distinguished_name
        .push(DnType::CommonName, format!("sipnab {stem} test server"));
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer)?;

    let cert = dir.path().join(format!("{stem}.pem"));
    let key = dir.path().join(format!("{stem}.key"));
    let ca_file = dir.path().join(format!("{stem}-ca.pem"));
    std::fs::write(&cert, leaf_cert.pem())?;
    std::fs::write(&key, leaf_key.serialize_pem())?;
    std::fs::write(&ca_file, ca_cert.pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(TestPki {
        cert: cert.to_string_lossy().into_owned(),
        key: key.to_string_lossy().into_owned(),
        ca_file: ca_file.to_string_lossy().into_owned(),
        ca: ca_cert.der().clone(),
        dir,
    })
}

impl TestPki {
    /// `[cert_flag, cert, key_flag, key]` for a listener's pair of flags.
    pub fn args<'a>(&'a self, cert_flag: &'a str, key_flag: &'a str) -> [&'a str; 4] {
        [cert_flag, &self.cert, key_flag, &self.key]
    }

    /// Make the key file readable by every user on the host.
    #[cfg(unix)]
    pub fn make_key_world_readable(&self) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&self.key, std::fs::Permissions::from_mode(0o644))
    }
}

/// One HTTP/1.1 response read over TLS.
#[derive(Debug)]
pub struct HttpsResponse {
    /// The status code.
    pub status: u16,
    /// The raw header block, status line included.
    pub head: String,
    /// The body.
    pub body: String,
}

/// Send `request` (a complete HTTP/1.1 request without a `Host` header line,
/// which this adds) over HTTPS to `addr`, trusting only `ca`.
///
/// # Returns
///
/// The response, or the error text when the TLS handshake or the exchange
/// failed. A test about a refused handshake asserts on that text.
pub fn https_exchange(
    addr: &str,
    request_line: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    ca: &rustls::pki_types::CertificateDer<'static>,
    timeout: std::time::Duration,
) -> Result<HttpsResponse, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(ca.clone())
        .map_err(|e| format!("trust store: {e}"))?;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("protocol versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let port = addr.rsplit_once(':').map(|(_, p)| p).unwrap_or_default();
    let target = format!("127.0.0.1:{port}");
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1")
        .map_err(|e| format!("IP server name: {e}"))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
        .map_err(|e| format!("client: {e}"))?;
    let sock = std::net::TcpStream::connect(&target).map_err(|e| format!("connect: {e}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let mut out = format!("{request_line}\r\nHost: {target}\r\nConnection: close\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");
    tls.write_all(out.as_bytes())
        .and_then(|()| tls.write_all(body))
        .map_err(|e| format!("handshake or write: {e}"))?;
    let mut raw = Vec::new();
    match tls.read_to_end(&mut raw) {
        Ok(_) => {}
        // A peer that closes without close_notify: what was read still counts.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => {}
        Err(e) => return Err(format!("read: {e}")),
    }
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("no status line in response:\n{text}"))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .map(|(h, b)| (h.to_string(), b.to_string()))
        .unwrap_or_else(|| (text.to_string(), String::new()));
    Ok(HttpsResponse { status, head, body })
}

/// `GET path` over HTTPS, trusting only `ca`: `(status, body)`, or the error
/// text when the handshake or the exchange failed.
pub fn https_get(
    addr: &str,
    path: &str,
    ca: &rustls::pki_types::CertificateDer<'static>,
    timeout: std::time::Duration,
) -> Result<(u16, String), String> {
    https_exchange(addr, &format!("GET {path} HTTP/1.1"), &[], &[], ca, timeout)
        .map(|r| (r.status, r.body))
}

/// Send a plain-HTTP `GET path` to `addr` and return whatever came back
/// before the peer closed or `timeout` passed.
pub fn plain_http_get(
    addr: &str,
    path: &str,
    timeout: std::time::Duration,
) -> std::io::Result<String> {
    let mut sock = std::net::TcpStream::connect(addr)?;
    sock.set_read_timeout(Some(timeout)).ok();
    let _ = sock.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    let mut raw = Vec::new();
    let _ = sock.read_to_end(&mut raw);
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

// Panicking forms of the functions above, for callers not yet converted to
// return a `Result`. Each is removed when its last caller is converted;
// `unwrap_ratchet_test` counts the `expect` in each.

/// [`test_pki`], panicking on error.
pub fn test_pki_or_panic(stem: &str) -> TestPki {
    test_pki(stem).expect("test_pki")
}

/// [`plain_http_get`], panicking on error.
pub fn plain_http_get_or_panic(addr: &str, path: &str, timeout: std::time::Duration) -> String {
    plain_http_get(addr, path, timeout).expect("plain_http_get")
}

impl TestPki {
    /// [`TestPki::make_key_world_readable`], panicking on error.
    #[cfg(unix)]
    pub fn make_key_world_readable_or_panic(&self) {
        self.make_key_world_readable()
            .expect("TestPki::make_key_world_readable")
    }
}
