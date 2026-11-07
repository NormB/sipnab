// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
//! For client certificates (`--api-tls-client-ca`, `--mcp-tls-client-ca`)
//! [`client_ca`] makes a second, separate CA and issues client certificates
//! from it: current, expired, not yet valid, or for server use only. The lib's
//! own unit tests (`src/tls_listener.rs`) mount this file too, so in-process
//! and real-binary handshakes use the same certificates.
//!
//! Every name is a reserved one (`example.com`); the keys are generated per
//! test and never written outside a temporary directory.
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

/// When a client certificate is valid, relative to now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// Valid now: from 2020 to 4096.
    Current,
    /// Expired: valid only during 2020.
    Expired,
    /// Not yet valid: valid only from 2090.
    NotYetValid,
    /// Valid from 2020 until this instant, which may be a second from now.
    Until(std::time::SystemTime),
}

/// The names a client certificate carries.
#[derive(Debug, Clone)]
pub struct Names {
    /// The subject's common name; `None` leaves the subject empty.
    pub cn: Option<String>,
    /// DNS subject alternative names.
    pub dns: Vec<String>,
    /// URI subject alternative names.
    pub uris: Vec<String>,
}

impl Names {
    /// The names [`ClientCa::issue`] gives `name`.
    pub fn member(name: &str) -> Self {
        Self {
            cn: Some(name.to_string()),
            dns: vec![format!("{name}.fleet.example.com")],
            uris: vec![format!("spiffe://fleet.example.com/member/{name}")],
        }
    }
}

/// A CA that issues client certificates, with its certificate written as a
/// PEM file for a `--*-tls-client-ca` flag.
pub struct ClientCa {
    /// Holds the files; removed on drop.
    pub dir: tempfile::TempDir,
    /// The CA certificate (PEM file).
    pub ca_file: String,
    /// The CA's certificate and key, which sign the client certificates.
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    /// The certificates between this CA and the root, nearest first: empty
    /// for a root. A client certificate this CA issues is sent with them.
    above: Vec<rustls::pki_types::CertificateDer<'static>>,
}

/// A client certificate and its key, in memory for a rustls client and as
/// PEM files for curl.
pub struct ClientCert {
    /// The certificate, then any intermediate CAs it needs, nearest first.
    pub chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// The certificate's private key (PKCS#8 DER).
    pub key_der: Vec<u8>,
    /// The certificate (PEM file).
    pub cert_file: String,
    /// The private key (PEM file), mode 0600.
    pub key_file: String,
}

impl ClientCert {
    /// The private key, as rustls takes it.
    pub fn key(&self) -> rustls::pki_types::PrivateKeyDer<'static> {
        rustls::pki_types::PrivateKeyDer::Pkcs8(self.key_der.clone().into())
    }
}

/// CA parameters named `name`, with no limit on the CAs below it.
fn ca_params(name: &str) -> rcgen::CertificateParams {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyUsagePurpose};
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(DnType::CommonName, name);
    params
}

/// A fresh CA for client certificates, named `sipnab <stem> client CA`, its
/// certificate written to `<stem>-client-ca.pem`.
pub fn client_ca(stem: &str) -> Result<ClientCa, TestError> {
    let dir = tempfile::tempdir()?;
    let issuer = rcgen::CertifiedIssuer::self_signed(
        ca_params(&format!("sipnab {stem} client CA")),
        rcgen::KeyPair::generate()?,
    )?;
    let ca_file = dir.path().join(format!("{stem}-client-ca.pem"));
    std::fs::write(&ca_file, issuer.pem())?;
    Ok(ClientCa {
        ca_file: ca_file.to_string_lossy().into_owned(),
        issuer,
        above: Vec::new(),
        dir,
    })
}

/// A self-signed client certificate for `name`, issued by no CA: the
/// certificate is its own issuer. Held in memory only; its file fields are
/// empty.
pub fn self_signed_client(name: &str) -> Result<ClientCert, TestError> {
    let key = rcgen::KeyPair::generate()?;
    let own = leaf_params(
        &Names::member(name),
        Validity::Current,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    )?
    .self_signed(&key)?;
    Ok(ClientCert {
        chain: vec![own.der().clone()],
        key_der: key.serialize_der(),
        cert_file: String::new(),
        key_file: String::new(),
    })
}

/// End-entity parameters for `names`, valid as `validity` says.
fn leaf_params(
    names: &Names,
    validity: Validity,
    usage: rcgen::ExtendedKeyUsagePurpose,
) -> Result<rcgen::CertificateParams, TestError> {
    use rcgen::{CertificateParams, DnType, IsCa, SanType, date_time_ymd};
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::ExplicitNoCa;
    params.distinguished_name = rcgen::DistinguishedName::new();
    if let Some(cn) = &names.cn {
        params
            .distinguished_name
            .push(DnType::CommonName, cn.as_str());
        params
            .distinguished_name
            .push(DnType::OrganizationName, "sipnab test fleet");
    }
    let mut sans = Vec::new();
    for d in &names.dns {
        sans.push(SanType::DnsName(d.as_str().try_into()?));
    }
    for u in &names.uris {
        sans.push(SanType::URI(u.as_str().try_into()?));
    }
    params.subject_alt_names = sans;
    params.extended_key_usages = vec![usage];
    (params.not_before, params.not_after) = match validity {
        Validity::Current => (date_time_ymd(2020, 1, 1), date_time_ymd(4096, 1, 1)),
        Validity::Expired => (date_time_ymd(2020, 1, 1), date_time_ymd(2021, 1, 1)),
        Validity::NotYetValid => (date_time_ymd(2090, 1, 1), date_time_ymd(2091, 1, 1)),
        Validity::Until(end) => (date_time_ymd(2020, 1, 1), end.into()),
    };
    Ok(params)
}

impl ClientCa {
    /// A client certificate for `name`: subject `CN=<name>,O=sipnab test
    /// fleet`, DNS name `<name>.fleet.example.com`, URI
    /// `spiffe://fleet.example.com/member/<name>`, extended key usage
    /// `clientAuth`, valid as `validity` says.
    pub fn issue(&self, name: &str, validity: Validity) -> Result<ClientCert, TestError> {
        self.issue_named(
            name,
            &Names::member(name),
            validity,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )
    }

    /// As [`Self::issue`], but its extended key usage is `serverAuth` only:
    /// a certificate made for a server, which a client must not use.
    pub fn issue_server_only(&self, name: &str) -> Result<ClientCert, TestError> {
        self.issue_named(
            name,
            &Names::member(name),
            Validity::Current,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        )
    }

    /// A client certificate carrying exactly `names`, its files named
    /// `<file>.pem` and `<file>.key`.
    pub fn issue_named(
        &self,
        file: &str,
        names: &Names,
        validity: Validity,
        usage: rcgen::ExtendedKeyUsagePurpose,
    ) -> Result<ClientCert, TestError> {
        let key = rcgen::KeyPair::generate()?;
        let cert = leaf_params(names, validity, usage)?.signed_by(&key, &self.issuer)?;
        let cert_file = self.dir.path().join(format!("{file}.pem"));
        let key_file = self.dir.path().join(format!("{file}.key"));
        std::fs::write(&cert_file, cert.pem())?;
        std::fs::write(&key_file, key.serialize_pem())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))?;
        }
        let mut chain = vec![cert.der().clone()];
        chain.extend(self.above.iter().cloned());
        Ok(ClientCert {
            chain,
            key_der: key.serialize_der(),
            cert_file: cert_file.to_string_lossy().into_owned(),
            key_file: key_file.to_string_lossy().into_owned(),
        })
    }

    /// An intermediate CA this CA signs. Its `ca_file` holds the
    /// intermediate alone; the certificates it issues carry it, and this
    /// CA's own intermediates, in their chain.
    pub fn intermediate(&self, stem: &str) -> Result<ClientCa, TestError> {
        let dir = tempfile::tempdir()?;
        let issuer = rcgen::CertifiedIssuer::signed_by(
            ca_params(&format!("sipnab {stem} intermediate CA")),
            rcgen::KeyPair::generate()?,
            &self.issuer,
        )?;
        let ca_file = dir.path().join(format!("{stem}-intermediate.pem"));
        std::fs::write(&ca_file, issuer.pem())?;
        let mut above = vec![issuer.der().clone()];
        above.extend(self.above.iter().cloned());
        Ok(ClientCa {
            ca_file: ca_file.to_string_lossy().into_owned(),
            issuer,
            above,
            dir,
        })
    }

    /// This CA's certificate, as PEM.
    pub fn pem(&self) -> String {
        self.issuer.pem()
    }

    /// This CA's own certificate and key, presented as a client
    /// certificate: a CA posing as an end entity.
    pub fn as_client(&self) -> ClientCert {
        ClientCert {
            chain: vec![self.issuer.der().clone()],
            key_der: self.issuer.key().serialize_der(),
            cert_file: String::new(),
            key_file: String::new(),
        }
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
    https_exchange_as(addr, request_line, headers, body, ca, None, timeout)
}

/// [`https_exchange`], presenting `client`'s certificate when the server asks
/// for one; `None` presents none.
///
/// # Returns
///
/// As [`https_exchange`]. Over TLS 1.3 the server checks a client
/// certificate after the client has finished its side of the handshake, so a
/// refusal arrives as an alert on the first read: the error text then starts
/// `read:` and names the alert.
pub fn https_exchange_as(
    addr: &str,
    request_line: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    ca: &rustls::pki_types::CertificateDer<'static>,
    client: Option<&ClientCert>,
    timeout: std::time::Duration,
) -> Result<HttpsResponse, String> {
    https_exchange_on(
        addr,
        Exchange {
            request_line,
            headers,
            body,
            ca,
            client,
            tls12_only: false,
            timeout,
        },
    )
}

/// One HTTPS exchange, as [`https_exchange_on`] makes it.
pub struct Exchange<'a> {
    /// The request line, such as `GET /health HTTP/1.1`.
    pub request_line: &'a str,
    /// Header lines beyond `Host` and `Connection`.
    pub headers: &'a [(&'a str, &'a str)],
    /// The request body.
    pub body: &'a [u8],
    /// The only CA the client trusts for the server.
    pub ca: &'a rustls::pki_types::CertificateDer<'static>,
    /// The client certificate to present, if any.
    pub client: Option<&'a ClientCert>,
    /// Offer TLS 1.2 only, rather than TLS 1.2 and 1.3.
    pub tls12_only: bool,
    /// The read timeout.
    pub timeout: std::time::Duration,
}

/// [`https_exchange_as`] with every option: see [`Exchange`].
pub fn https_exchange_on(addr: &str, x: Exchange<'_>) -> Result<HttpsResponse, String> {
    let Exchange {
        request_line,
        headers,
        body,
        ca,
        client,
        tls12_only,
        timeout,
    } = x;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(ca.clone())
        .map_err(|e| format!("trust store: {e}"))?;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if tls12_only {
        &[&rustls::version::TLS12]
    } else {
        rustls::DEFAULT_VERSIONS
    };
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| format!("protocol versions: {e}"))?
        .with_root_certificates(roots);
    let config = match client {
        Some(client) => builder
            .with_client_auth_cert(client.chain.clone(), client.key())
            .map_err(|e| format!("client certificate: {e}"))?,
        None => builder.with_no_client_auth(),
    };
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

/// Whether the server still holds `sock` open: nothing on it says the server
/// closed or reset it. Asked without blocking and without consuming a byte.
///
/// The silent-client tests use it in place of a bound on elapsed time. A
/// listener that runs each handshake inline serves a second client only after
/// it gives up on the silent one and closes it, at its handshake timeout. So
/// a second client served while the silent connection is still open proves
/// the handshakes ran side by side, however slowly the host ran.
///
/// # Errors
///
/// The socket's blocking mode cannot be changed.
pub fn server_still_holds(sock: &std::net::TcpStream) -> std::io::Result<bool> {
    sock.set_nonblocking(true)?;
    let mut byte = [0u8; 1];
    let open = match sock.peek(&mut byte) {
        // An end of stream: the server closed its side.
        Ok(0) => false,
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
        // A reset or any other error: the connection is gone.
        Err(_) => false,
    };
    sock.set_nonblocking(false)?;
    Ok(open)
}
