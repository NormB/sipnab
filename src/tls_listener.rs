// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The HTTPS listener shared by the servers built on axum: the REST API
//! (`--api-tls-cert`) and MCP over HTTP (`--mcp-tls-cert`).
//!
//! One accept loop, one handshake timeout and one cap on handshakes in
//! progress, so the two cannot drift apart on how they treat a slow or
//! hostile client. The certificate and key are read by
//! [`crate::tls_files::server_config`], which the metrics endpoint and the
//! HEP listener share too.
//!
//! With a client CA (`--api-tls-client-ca`, `--mcp-tls-client-ca`) the
//! handshake also verifies the client's certificate. [`into_tls_service`]
//! hands each request the verified client as a [`ClientIdentity`] request
//! extension, beside the usual `ConnectInfo<SocketAddr>`, and the accept loop
//! logs who connected and why a refused certificate was refused.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// How long a connecting client has to finish its TLS handshake.
///
/// A client that connects and says nothing would otherwise hold its task and
/// its handshake slot forever. Ten seconds is generous for a handshake over
/// any real path and short enough that a slow drip of silent connections
/// cannot hold [`MAX_HANDSHAKES`] slots for long.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS handshakes a listener runs at once before it sheds new connections.
///
/// Handshakes run off the accept path, one task each, so a silent client
/// cannot stall anyone else's; this bounds how many such tasks a flood of
/// connections can create. A connection arriving past it is closed at once.
pub const MAX_HANDSHAKES: usize = 256;

/// The application protocols offered in the TLS handshake: `http/1.1` only.
/// Both servers run on `axum::serve`, and this build does not enable axum's
/// `http2` feature, so offering `h2` would promise a protocol the server
/// does not speak.
pub const HTTP1_ALPN: &[&[u8]] = &[b"http/1.1"];

/// A TCP listener that hands axum only connections whose TLS handshake has
/// completed.
///
/// axum calls [`axum::serve::Listener::accept`] serially, so a handshake run
/// inside it would let one client that connects and never speaks stall every
/// other client (Slowloris). Instead a background task accepts TCP
/// connections and gives each handshake its own task, bounded by a timeout
/// and by a cap on handshakes in progress; finished connections arrive on a
/// channel that `accept` reads.
pub(crate) struct TlsListener {
    /// Connections whose handshake completed, with their peer address.
    ready: tokio::sync::mpsc::Receiver<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        SocketAddr,
    )>,
    /// The bound address, captured before the socket moved into the task.
    local: SocketAddr,
    /// The accept task; aborted when the listener is dropped, which closes
    /// the socket.
    acceptor: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    /// Start accepting on `tcp`.
    ///
    /// # Arguments
    ///
    /// * `surface` — the listener being served (`"API TLS"`, `"MCP TLS"`),
    ///   named in every log line.
    /// * `tcp` — the bound listener.
    /// * `config` — the TLS configuration to serve.
    /// * `handshake_timeout` — how long one client has to finish its
    ///   handshake before its connection is dropped.
    /// * `max_handshakes` — handshakes in progress at once; a connection
    ///   arriving past it is closed without one.
    ///
    /// # Errors
    ///
    /// The listener's local address cannot be read.
    ///
    /// # Side effects
    ///
    /// Spawns the accept task on the current tokio runtime.
    pub(crate) fn new(
        surface: &'static str,
        tcp: tokio::net::TcpListener,
        config: Arc<rustls::ServerConfig>,
        handshake_timeout: Duration,
        max_handshakes: usize,
    ) -> std::io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, ready) = tokio::sync::mpsc::channel(max_handshakes.max(1));
        let acceptor = tokio::spawn(accept_tls(
            surface,
            tcp,
            tokio_rustls::TlsAcceptor::from(config),
            tx,
            handshake_timeout,
            Arc::new(tokio::sync::Semaphore::new(max_handshakes)),
        ));
        Ok(Self {
            ready,
            local,
            acceptor,
        })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.acceptor.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(conn) => conn,
            // The accept task only ends when this receiver is gone, so this
            // arm is unreachable while `self` exists; waiting forever is what
            // a listener with nothing more to offer does.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// The TLS configuration of an HTTPS listener: the server's certificate and
/// key, and the client certificates `client_auth` asks for.
///
/// The one builder for the REST API and MCP over HTTP (and the fleet center,
/// which serves through the REST API's listener), so their client
/// certificate rules cannot drift apart. The caller has already checked
/// `client_auth` with [`crate::cli::client_auth_problem`].
///
/// # Arguments
///
/// * `files` — the certificate chain and the private key.
/// * `client_auth` — the client CA and the mode.
/// * `surface` — the listener, named in every error (`"API TLS"`).
///
/// # Errors
///
/// As [`crate::tls_files::server_config`] and
/// [`crate::tls_files::client_verifier`].
///
/// # Side effects
///
/// Reads the certificate, key and client CA files.
pub(crate) fn https_config(
    files: (&std::path::Path, &std::path::Path),
    settings: (&str, &str),
    client_auth: &crate::config::ClientCertAuth,
    surface: &str,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let clients = match client_auth.ca.as_deref() {
        Some(ca) if client_auth.effective_mode() == crate::config::ClientAuthMode::Off => {
            tracing::warn!(
                "{surface} asks clients for no certificate: the client-auth mode is off, \
                 so the client CA {ca} is not read"
            );
            None
        }
        Some(ca) => crate::tls_files::client_verifier(
            std::path::Path::new(ca),
            client_auth.effective_mode(),
            surface,
        )?,
        None => None,
    };
    if clients.is_some() {
        tracing::info!(
            "{surface} asks clients for a certificate ({})",
            client_auth.effective_mode().name()
        );
    }
    crate::tls_files::server_config_with_clients(
        files.0,
        files.1,
        surface,
        settings,
        HTTP1_ALPN.iter().map(|p| p.to_vec()).collect(),
        clients,
    )
}

/// The client a TLS connection verified a certificate for.
///
/// Built only from a certificate rustls has already verified against the
/// listener's client CA, so every field is as trustworthy as that CA. It
/// reaches request handlers as a request extension (see
/// [`into_tls_service`]); a request on a connection without a verified
/// certificate carries none.
///
/// A certificate never grants a scope: the bearer token still decides what a
/// request may do. This names the client in logs and audit records, and lets
/// a caller tell a verified name from one the client only claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientIdentity {
    /// The subject distinguished name, as RFC 4514 writes it (the last RDN
    /// first, as `openssl x509 -noout -subject -nameopt RFC2253` prints
    /// it). Empty for an empty subject.
    pub subject: String,
    /// The certificate's DNS subject alternative names, in certificate order.
    pub dns_names: Vec<String>,
    /// The certificate's URI subject alternative names, in certificate order
    /// (a SPIFFE ID is one).
    pub uris: Vec<String>,
}

impl ClientIdentity {
    /// The identity in a verified end-entity certificate, or `None` when the
    /// certificate cannot be parsed (which rustls, having verified it, has
    /// already ruled out).
    pub(crate) fn from_leaf(leaf: &rustls::pki_types::CertificateDer<'_>) -> Option<Self> {
        let cert = webpki::EndEntityCert::try_from(leaf).ok()?;
        Some(Self {
            subject: render_name(cert.subject()),
            dns_names: cert.valid_dns_names().map(str::to_string).collect(),
            uris: cert.valid_uri_names().map(str::to_string).collect(),
        })
    }

    /// The one name that stands for this client: the first URI SAN, else the
    /// first DNS SAN, else the subject. A SAN first because it is the name a
    /// CA is asked to vouch for, and the subject is often a free-form label.
    ///
    /// The MCP audit record names a client by it; the REST API logs every
    /// field instead.
    #[cfg(any(test, feature = "mcp-http"))]
    pub(crate) fn label(&self) -> &str {
        self.uris
            .first()
            .or_else(|| self.dns_names.first())
            .map_or(self.subject.as_str(), String::as_str)
    }
}

/// The subject (or issuer) `Name` of a certificate as an RFC 4514 string,
/// from its DER contents without the outer `SEQUENCE` header (what
/// `webpki::Cert::subject` returns).
///
/// The RDNs are written last first, `,` between RDNs and `+` between the
/// attributes of a multi-valued RDN. Attribute types sipnab knows are written
/// by name (`CN`, `O`, `OU`, `C`, `L`, `ST`, `DC`, `serialNumber`,
/// `emailAddress`, `UID`); any other by its dotted OID. A value in a string
/// type is written as text with RFC 4514's escapes; any other as `#` and its
/// DER in hex, as [RFC 4514 section 2.4](https://www.rfc-editor.org/rfc/rfc4514.html#section-2.4) says.
///
/// A name that does not parse is written as `#` and the hex of all of it:
/// still exact, never a panic, and never a string that looks like a parsed
/// name.
pub(crate) fn render_name(der: &[u8]) -> String {
    rdns(der).map_or_else(
        || {
            let mut out = String::from("#");
            push_hex(&mut out, der);
            out
        },
        |rdns| rdns.join(","),
    )
}

/// The RDNs of a `Name`'s contents, each rendered, last first; `None` when
/// any part does not parse.
fn rdns(mut der: &[u8]) -> Option<Vec<String>> {
    let mut out = Vec::new();
    while !der.is_empty() {
        let (tag, mut set, rest) = der_tlv(der)?;
        // RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
        if tag != 0x31 || set.is_empty() {
            return None;
        }
        let mut attributes = Vec::new();
        while !set.is_empty() {
            let (tag, atv, after) = der_tlv(set)?;
            if tag != 0x30 {
                return None;
            }
            attributes.push(attribute(atv)?);
            set = after;
        }
        out.push(attributes.join("+"));
        der = rest;
    }
    out.reverse();
    Some(out)
}

/// One `AttributeTypeAndValue` as `type=value`.
fn attribute(atv: &[u8]) -> Option<String> {
    let (tag, oid, rest) = der_tlv(atv)?;
    if tag != 0x06 {
        return None;
    }
    let (value_tag, value, after) = der_tlv(rest)?;
    if !after.is_empty() {
        return None;
    }
    let mut out = attribute_name(oid)?;
    out.push('=');
    match string_value(value_tag, value) {
        Some(text) => push_escaped(&mut out, &text),
        None => {
            // RFC 4514 section 2.4: `#` and the hex of the value's whole BER
            // (here DER) encoding, header included.
            // `after` is empty, so `rest` is exactly the value's TLV.
            out.push('#');
            push_hex(&mut out, rest);
        }
    }
    Some(out)
}

/// The short name RFC 4514 (and OpenSSL) gives an attribute type, or its
/// dotted OID.
fn attribute_name(oid: &[u8]) -> Option<String> {
    let known = match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x05] => "serialNumber",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01] => "UID",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
        _ => return dotted_oid(oid),
    };
    Some(known.to_string())
}

/// An OID's contents in dotted form; `None` when malformed.
fn dotted_oid(oid: &[u8]) -> Option<String> {
    let mut arcs: Vec<u64> = Vec::new();
    let mut arc: u64 = 0;
    let mut pending = false;
    for &b in oid {
        arc = arc.checked_mul(128)?.checked_add(u64::from(b & 0x7f))?;
        pending = b & 0x80 != 0;
        if !pending {
            arcs.push(arc);
            arc = 0;
        }
    }
    let (&first, rest) = arcs.split_first()?;
    if pending {
        return None;
    }
    let (a, b) = match first {
        0..=39 => (0, first),
        40..=79 => (1, first - 40),
        _ => (2, first - 80),
    };
    let mut out = format!("{a}.{b}");
    for arc in rest {
        out.push('.');
        out.push_str(&arc.to_string());
    }
    Some(out)
}

/// The text of a value in one of the directory string types, or `None` for
/// any other type (or bytes that are not that type's text).
fn string_value(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        // UTF8String
        0x0c => std::str::from_utf8(value).ok().map(str::to_string),
        // PrintableString, IA5String, VisibleString
        0x13 | 0x16 | 0x1a => value
            .is_ascii()
            .then(|| String::from_utf8_lossy(value).into_owned()),
        // BMPString: UCS-2, big-endian.
        0x1e => {
            let (pairs, odd) = value.as_chunks::<2>();
            if !odd.is_empty() {
                return None;
            }
            let units: Vec<u16> = pairs.iter().map(|p| u16::from_be_bytes(*p)).collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

/// Append `text` with [RFC 4514 section 2.4](https://www.rfc-editor.org/rfc/rfc4514.html#section-2.4)'s escapes: `\` before `,` `+`
/// `"` `\` `<` `>` `;` anywhere, before `#` or a space at the start and a
/// space at the end, and a control character as `\XX`.
fn push_escaped(out: &mut String, text: &str) {
    let last = text.chars().count().saturating_sub(1);
    for (i, c) in text.chars().enumerate() {
        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => {
                out.push('\\');
                out.push(c);
            }
            '#' if i == 0 => out.push_str("\\#"),
            ' ' if i == 0 || i == last => out.push_str("\\ "),
            c if c.is_control() => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    out.push_str(&format!("\\{b:02X}"));
                }
            }
            c => out.push(c),
        }
    }
}

/// Append `bytes` as lowercase hex.
fn push_hex(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
}

/// One DER TLV at the start of `input`: `(tag, contents, the rest)`; `None`
/// when it is truncated, uses a high tag number, or a length past four bytes.
fn der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let (digits, rest) = rest.split_at_checked(count)?;
        let len = digits.iter().try_fold(0usize, |len, &d| {
            len.checked_mul(256)?.checked_add(usize::from(d))
        })?;
        (len, rest)
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// What axum hands a request on a [`TlsListener`] connection: the peer's
/// address and the verified client, if the handshake verified one.
///
/// [`into_tls_service`] turns it into the `ConnectInfo<SocketAddr>` every
/// handler already reads and a [`ClientIdentity`] extension.
#[derive(Clone, Debug)]
pub(crate) struct TlsConnectInfo {
    /// The peer's socket address.
    addr: SocketAddr,
    /// The verified client certificate's identity; `None` without one.
    client: Option<ClientIdentity>,
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for TlsConnectInfo
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        Self {
            addr: *stream.remote_addr(),
            client: verified_client(stream.io()),
        }
    }
}

/// The identity in the certificate the client of `stream` presented, which
/// the handshake has verified; `None` when it presented none.
fn verified_client(
    stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<ClientIdentity> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(<[_]>::first)
        .and_then(ClientIdentity::from_leaf)
}

/// `router` as the service axum serves on a [`TlsListener`]: each request
/// carries `ConnectInfo<SocketAddr>`, as on a plain listener, and a
/// [`ClientIdentity`] extension when the connection verified a client
/// certificate.
///
/// The one way both HTTPS servers (and the fleet center, which serves through
/// the REST API's listener) hand handlers the verified client, so none can
/// read it from somewhere a client could write.
pub(crate) fn into_tls_service(
    router: axum::Router,
) -> axum::extract::connect_info::IntoMakeServiceWithConnectInfo<axum::Router, TlsConnectInfo> {
    router
        .layer(axum::middleware::from_fn(stamp_tls_peer))
        .into_make_service_with_connect_info::<TlsConnectInfo>()
}

/// Copy the connection's [`TlsConnectInfo`] into the request: the address as
/// `ConnectInfo<SocketAddr>` and the client, when there is one, as a
/// [`ClientIdentity`].
async fn stamp_tls_peer(
    axum::extract::ConnectInfo(info): axum::extract::ConnectInfo<TlsConnectInfo>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(info.addr));
    if let Some(client) = info.client {
        request.extensions_mut().insert(client);
    }
    next.run(request).await
}

/// The rustls error behind a failed handshake when the failure was the
/// client's certificate: none sent where one is required, or one that did not
/// verify. `None` for any other failure.
fn client_certificate_refusal(e: &std::io::Error) -> Option<&rustls::Error> {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .filter(|why| {
            matches!(
                why,
                rustls::Error::NoCertificatesPresented | rustls::Error::InvalidCertificate(_)
            )
        })
}

/// The accept loop behind [`TlsListener`]: take TCP connections, run each
/// handshake in its own task, send the completed ones to `ready`.
///
/// # Side effects
///
/// Accepts connections until `ready`'s receiver is dropped. Logs a failed or
/// timed-out handshake at debug and a shed connection at debug; neither stops
/// the loop, so one bad client never takes the server down.
async fn accept_tls(
    surface: &'static str,
    tcp: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    ready: tokio::sync::mpsc::Sender<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        SocketAddr,
    )>,
    handshake_timeout: Duration,
    slots: Arc<tokio::sync::Semaphore>,
) {
    while !ready.is_closed() {
        let (socket, peer) = match tcp.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                // Per-connection errors (the peer reset before we took it)
                // say nothing about the listener; anything else — EMFILE
                // above all — would spin hot if retried at once. axum's own
                // TcpListener does the same.
                if !is_connection_error(&e) {
                    tracing::warn!("{surface} accept error: {e}; retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!("{surface}: {peer} shed, handshake slots full");
            drop(socket);
            continue;
        };
        let acceptor = acceptor.clone();
        let ready = ready.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(handshake_timeout, acceptor.accept(socket)).await {
                Ok(Ok(stream)) => {
                    if let Some(client) = verified_client(&stream) {
                        // Debug-formatted strings: a name in a certificate
                        // is the CA's to choose, and quoting and escaping it
                        // keeps one line one line.
                        tracing::info!(
                            "{surface}: {peer} presented a verified client certificate: \
                             subject={:?} dns={:?} uri={:?}",
                            client.subject,
                            client.dns_names,
                            client.uris
                        );
                    }
                    // The slot is held until axum has the connection, so a
                    // backlog of finished handshakes counts against the cap.
                    let _ = ready.send((stream, peer)).await;
                }
                Ok(Err(e)) => match client_certificate_refusal(&e) {
                    Some(why) => tracing::warn!(
                        "{surface}: refused the TLS handshake with {peer}: \
                         client certificate: {why}"
                    ),
                    None => tracing::debug!("{surface} handshake with {peer} failed: {e}"),
                },
                Err(_) => tracing::debug!(
                    "{surface} handshake with {peer} timed out after {handshake_timeout:?}"
                ),
            }
            drop(slot);
        });
    }
}

/// Whether an `accept` error belongs to one connection rather than to the
/// listener.
pub(crate) fn is_connection_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

/// The certificates the handshake tests use, shared with the integration
/// tests so both sides test against one PKI.
#[cfg(test)]
#[path = "../tests/support/tls_pki.rs"]
mod tls_pki;

#[cfg(test)]
mod tests {
    use super::tls_pki::{ClientCa, ClientCert, TestPki, Validity, client_ca, test_pki};
    use super::*;
    use crate::config::ClientAuthMode;

    /// The error a fallible test returns.
    type TestError = Box<dyn std::error::Error>;

    /// A running HTTPS server whose `/whoami` answers `<peer ip> <client>`,
    /// `<client>` being the verified client's [`ClientIdentity::label`] or
    /// `none`.
    struct Served {
        /// `127.0.0.1:<port>`.
        addr: String,
        /// The server's CA, for the client to trust.
        server_ca: rustls::pki_types::CertificateDer<'static>,
        /// The serve task; aborted on drop.
        task: tokio::task::JoinHandle<()>,
        /// Keeps the server's files.
        _pki: TestPki,
    }

    impl Drop for Served {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// Answer `/whoami` from what [`into_tls_service`] stamped.
    async fn whoami(
        axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
        client: Option<axum::Extension<ClientIdentity>>,
    ) -> String {
        let name = client.map_or_else(|| "none".to_string(), |c| c.0.label().to_string());
        format!("{} {name}", peer.ip())
    }

    /// Serve `/whoami` over HTTPS, asking for client certificates from `ca`
    /// as `mode` says.
    async fn serve(ca: &ClientCa, mode: ClientAuthMode) -> Result<Served, TestError> {
        serve_file(&ca.ca_file, mode).await
    }

    /// [`serve`] with the client CA file named directly.
    async fn serve_file(ca_file: &str, mode: ClientAuthMode) -> Result<Served, TestError> {
        let pki = test_pki("mtls-server")?;
        let clients =
            crate::tls_files::client_verifier(std::path::Path::new(ca_file), mode, "API TLS")?;
        let config = crate::tls_files::server_config_with_clients(
            std::path::Path::new(&pki.cert),
            std::path::Path::new(&pki.key),
            "API TLS",
            crate::cli::API_TLS_FLAGS,
            HTTP1_ALPN.iter().map(|p| p.to_vec()).collect(),
            clients,
        )?;
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = tcp.local_addr()?.to_string();
        let listener = TlsListener::new("API TLS", tcp, config, Duration::from_secs(5), 8)?;
        let router = axum::Router::new().route("/whoami", axum::routing::get(whoami));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, into_tls_service(router)).await;
        });
        Ok(Served {
            addr,
            server_ca: pki.ca.clone(),
            task,
            _pki: pki,
        })
    }

    /// `GET /whoami` on `served`, presenting `client`: the body, or the
    /// client's error text when the handshake or the exchange failed.
    async fn ask(served: &Served, client: Option<&ClientCert>) -> Result<String, String> {
        ask_with(served, client, false).await
    }

    /// [`ask`], offering TLS 1.2 only when `tls12_only` is set.
    async fn ask_with(
        served: &Served,
        client: Option<&ClientCert>,
        tls12_only: bool,
    ) -> Result<String, String> {
        let addr = served.addr.clone();
        let ca = served.server_ca.clone();
        let chain = client.map(|c| (c.chain.clone(), c.key_der.clone()));
        tokio::task::spawn_blocking(move || {
            let owned = chain.map(|(chain, key_der)| ClientCert {
                chain,
                key_der,
                cert_file: String::new(),
                key_file: String::new(),
            });
            super::tls_pki::https_exchange_on(
                &addr,
                super::tls_pki::Exchange {
                    request_line: "GET /whoami HTTP/1.1",
                    headers: &[],
                    body: &[],
                    ca: &ca,
                    client: owned.as_ref(),
                    tls12_only,
                    timeout: Duration::from_secs(10),
                },
            )
            .map(|r| format!("{} {}", r.status, r.body))
        })
        .await
        .map_err(|e| format!("join: {e}"))?
    }

    /// Assert `answer` is a refused handshake, not a response.
    fn assert_refused(answer: &Result<String, String>, what: &str) {
        assert!(
            answer.is_err(),
            "{what} must not complete the handshake, but was served: {answer:?}"
        );
    }

    /// `required`: a client with a certificate from the client CA is served,
    /// and the handler sees who it is by its URI SAN.
    #[tokio::test]
    async fn required_serves_a_client_with_a_certificate_from_the_ca() -> Result<(), TestError> {
        let ca = client_ca("req-ok")?;
        let member = ca.issue("member-1", Validity::Current)?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        let answer = ask(&served, Some(&member)).await?;
        assert_eq!(
            answer, "200 127.0.0.1 spiffe://fleet.example.com/member/member-1",
            "a certificate the client CA issued is served, named by its URI SAN"
        );
        Ok(())
    }

    /// `required`: a handshake without a certificate is refused, and the
    /// listener goes on serving a client that has one.
    #[tokio::test]
    async fn required_refuses_a_handshake_without_a_certificate() -> Result<(), TestError> {
        let ca = client_ca("req-none")?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        let answer = ask(&served, None).await;
        assert_refused(&answer, "a client with no certificate");
        let err = answer.err().unwrap_or_default();
        assert!(
            err.contains("CertificateRequired"),
            "TLS 1.3 names the refusal certificate_required: {err}"
        );
        let member = ca.issue("member-2", Validity::Current)?;
        assert!(
            ask(&served, Some(&member)).await?.starts_with("200 "),
            "the listener still serves a good certificate after refusing a handshake"
        );
        Ok(())
    }

    /// A certificate issued by another CA is refused, in both modes that ask.
    #[tokio::test]
    async fn a_certificate_from_another_ca_is_refused() -> Result<(), TestError> {
        let ca = client_ca("trusted")?;
        let stranger = client_ca("stranger")?.issue("intruder", Validity::Current)?;
        for mode in [ClientAuthMode::Required, ClientAuthMode::Optional] {
            let served = serve(&ca, mode).await?;
            let answer = ask(&served, Some(&stranger)).await;
            assert_refused(&answer, &format!("{mode:?}: another CA's certificate"));
            let err = answer.err().unwrap_or_default();
            assert!(err.contains("UnknownCA"), "{mode:?}: {err}");
        }
        Ok(())
    }

    /// An expired certificate and one not yet valid are refused, though the
    /// client CA issued both.
    #[tokio::test]
    async fn a_certificate_outside_its_validity_period_is_refused() -> Result<(), TestError> {
        let ca = client_ca("validity")?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        for validity in [Validity::Expired, Validity::NotYetValid] {
            let cert = ca.issue("member-3", validity)?;
            let answer = ask(&served, Some(&cert)).await;
            assert_refused(&answer, &format!("a {validity:?} certificate"));
            let err = answer.err().unwrap_or_default();
            assert!(
                err.contains("CertificateExpired"),
                "{validity:?}: rustls answers certificate_expired for both: {err}"
            );
        }
        Ok(())
    }

    /// A certificate whose extended key usage is server authentication only
    /// is refused as a client certificate.
    #[tokio::test]
    async fn a_server_only_certificate_is_refused_as_a_client_certificate() -> Result<(), TestError>
    {
        let ca = client_ca("eku")?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        let cert = ca.issue_server_only("member-4")?;
        assert_refused(&ask(&served, Some(&cert)).await, "a serverAuth-only cert");
        Ok(())
    }

    /// `optional`: a client with no certificate is served with no identity; a
    /// client with one is served with its identity.
    #[tokio::test]
    async fn optional_serves_both_and_names_only_the_verified() -> Result<(), TestError> {
        let ca = client_ca("opt")?;
        let served = serve(&ca, ClientAuthMode::Optional).await?;
        assert_eq!(
            ask(&served, None).await?,
            "200 127.0.0.1 none",
            "optional serves a client with no certificate, and names nobody"
        );
        let member = ca.issue("member-5", Validity::Current)?;
        assert_eq!(
            ask(&served, Some(&member)).await?,
            "200 127.0.0.1 spiffe://fleet.example.com/member/member-5",
            "optional names a client whose certificate verified"
        );
        Ok(())
    }

    /// `off`: no certificate is asked for, so a client that holds one is
    /// served without an identity, exactly as before this setting existed.
    #[tokio::test]
    async fn off_asks_for_nothing_and_names_nobody() -> Result<(), TestError> {
        let ca = client_ca("off")?;
        let served = serve(&ca, ClientAuthMode::Off).await?;
        let member = ca.issue("member-6", Validity::Current)?;
        assert_eq!(
            ask(&served, Some(&member)).await?,
            "200 127.0.0.1 none",
            "off asks for no certificate, so a client that holds one is not named"
        );
        assert_eq!(
            ask(&served, None).await?,
            "200 127.0.0.1 none",
            "off serves a client with no certificate"
        );
        Ok(())
    }

    /// The identity reads the subject, the DNS names and the URIs.
    #[test]
    fn the_identity_reads_the_subject_and_both_kinds_of_san() -> Result<(), TestError> {
        let cert = client_ca("identity")?.issue("member-7", Validity::Current)?;
        let leaf = cert.chain.first().ok_or("one certificate")?;
        let identity = ClientIdentity::from_leaf(leaf).ok_or("a valid leaf parses")?;
        assert_eq!(
            identity,
            ClientIdentity {
                subject: "O=sipnab test fleet,CN=member-7".to_string(),
                dns_names: vec!["member-7.fleet.example.com".to_string()],
                uris: vec!["spiffe://fleet.example.com/member/member-7".to_string()],
            },
            "the identity holds the RFC 4514 subject and both SAN kinds, in order"
        );
        Ok(())
    }

    /// The label is the first URI, else the first DNS name, else the subject.
    #[test]
    fn the_label_prefers_a_uri_then_a_dns_name_then_the_subject() {
        let mut id = ClientIdentity {
            subject: "CN=s".to_string(),
            dns_names: vec!["d1.example.com".to_string(), "d2.example.com".to_string()],
            uris: vec!["spiffe://example.com/u1".to_string()],
        };
        assert_eq!(
            id.label(),
            "spiffe://example.com/u1",
            "a URI SAN comes first"
        );
        id.uris.clear();
        assert_eq!(
            id.label(),
            "d1.example.com",
            "with no URI, the first DNS SAN"
        );
        id.dns_names.clear();
        assert_eq!(id.label(), "CN=s", "with no SAN at all, the subject");
    }

    /// DER for one `AttributeTypeAndValue` in its own RDN `SET`.
    fn rdn(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
        let atv = tlv(0x30, &[tlv(0x06, oid), tlv(tag, value)].concat());
        tlv(0x31, &atv)
    }

    /// One short-form DER TLV.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(contents.len()).unwrap_or(u8::MAX)];
        out.extend_from_slice(contents);
        out
    }

    /// OID 2.5.4.3, commonName.
    const CN: &[u8] = &[0x55, 0x04, 0x03];
    /// OID 2.5.4.10, organizationName.
    const O: &[u8] = &[0x55, 0x04, 0x0a];

    /// RDNs come out last first, joined by `,`; known types by name.
    #[test]
    fn a_name_renders_last_rdn_first() {
        let der = [rdn(O, 0x0c, b"Example"), rdn(CN, 0x13, b"member")].concat();
        assert_eq!(
            render_name(&der),
            "CN=member,O=Example",
            "RFC 4514 writes the last RDN first"
        );
    }

    /// The attributes of a multi-valued RDN are joined by `+`.
    #[test]
    fn a_multi_valued_rdn_joins_with_plus() {
        let set = tlv(
            0x31,
            &[
                tlv(0x30, &[tlv(0x06, CN), tlv(0x0c, b"a")].concat()),
                tlv(0x30, &[tlv(0x06, O), tlv(0x0c, b"b")].concat()),
            ]
            .concat(),
        );
        assert_eq!(
            render_name(&set),
            "CN=a+O=b",
            "a multi-valued RDN joins its attributes with +"
        );
    }

    /// RFC 4514's special characters are escaped, so a value cannot forge an
    /// attribute: `,` `+` `"` `\` `<` `>` `;` anywhere, `#` and a space at the
    /// start, a space at the end, and control bytes as `\XX`.
    #[test]
    fn a_value_cannot_forge_an_attribute() {
        let der = rdn(CN, 0x0c, b"#a,O=x+y\"\\<>; \n ");
        assert_eq!(
            render_name(&der),
            r#"CN=\#a\,O=x\+y\"\\\<\>\; \0A\ "#,
            "every RFC 4514 special character is escaped"
        );
    }

    /// An unknown type is written by its dotted OID, and a value that is not a
    /// string type as `#` and its DER in hex.
    #[test]
    fn an_unknown_type_and_a_binary_value_are_written_exactly() {
        // 1.2.840.113549.1.9.99 (unassigned under pkcs-9), an OCTET STRING.
        let oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x63];
        let der = rdn(&oid, 0x04, &[0xde, 0xad]);
        assert_eq!(
            render_name(&der),
            "1.2.840.113549.1.9.99=#0402dead",
            "an unknown type is its dotted OID and a binary value is # and its DER"
        );
    }

    /// A BMPString is read as big-endian UCS-2; an odd length, or a
    /// PrintableString holding a byte that is not ASCII, is not text and is
    /// written as hex.
    #[test]
    fn a_bmp_string_is_read_big_endian_and_bad_text_is_hex() {
        assert_eq!(
            render_name(&rdn(CN, 0x1e, &[0, b'a', 0, b'b'])),
            "CN=ab",
            "a BMPString is big-endian UCS-2"
        );
        assert_eq!(
            render_name(&rdn(CN, 0x1e, &[0, b'a', 0])),
            "CN=#1e03006100",
            "an odd-length BMPString is not text, so it is written as hex"
        );
        assert_eq!(
            render_name(&rdn(CN, 0x13, &[0xff])),
            "CN=#1301ff",
            "a PrintableString with a non-ASCII byte is not text, so it is hex"
        );
    }

    /// A name that does not parse is written whole as hex, never partly as a
    /// name, and never panics.
    #[test]
    fn a_malformed_name_is_written_as_hex() {
        for der in [
            vec![0x31, 0x05, 0x30],
            vec![0x31],
            vec![0x30, 0x00],
            vec![0x31, 0x84, 0xff, 0xff, 0xff, 0xff],
        ] {
            let mut want = "#".to_string();
            for b in &der {
                want.push_str(&format!("{b:02x}"));
            }
            assert_eq!(render_name(&der), want, "{der:02x?}");
        }
        assert_eq!(render_name(&[]), "", "an empty subject is empty");
    }

    /// Only a failure about the client's certificate is reported as a
    /// refused certificate; any other handshake failure is not.
    #[test]
    fn only_client_certificate_failures_are_named_as_refusals() {
        let wrap = |e: rustls::Error| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
        // Each case is named by a fixed label, not by printing the error:
        // CodeQL's cleartext-logging query reads a certificate error as
        // certificate material.
        for (what, e) in [
            ("no certificate", rustls::Error::NoCertificatesPresented),
            (
                "an expired certificate",
                rustls::Error::InvalidCertificate(rustls::CertificateError::Expired),
            ),
            (
                "an unknown issuer",
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
            ),
        ] {
            assert!(
                client_certificate_refusal(&wrap(e)).is_some(),
                "{what} is about the client certificate"
            );
        }
        for (what, e) in [
            (
                "a client offering no TLS 1.2",
                wrap(rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::Tls12NotOffered,
                )),
            ),
            ("a decrypt error", wrap(rustls::Error::DecryptError)),
            (
                "a reset",
                std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            ),
        ] {
            assert!(
                client_certificate_refusal(&e).is_none(),
                "{what} is not about a client certificate"
            );
        }
    }

    /// The text of the error `client_verifier` returns for `ca` in `mode`.
    fn verifier_error(ca: &std::path::Path, mode: ClientAuthMode) -> Result<String, TestError> {
        match crate::tls_files::client_verifier(ca, mode, "API TLS") {
            Ok(_) => Err(format!("{} must be refused", ca.display()).into()),
            Err(e) => Ok(format!("{e:#}")),
        }
    }

    /// A client CA file any user can write is refused: whoever writes to it
    /// chooses which clients the listener admits.
    #[cfg(unix)]
    #[test]
    fn a_world_writable_client_ca_is_refused() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt;
        let ca = client_ca("writable")?;
        let path = std::path::Path::new(&ca.ca_file);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
        let err = verifier_error(path, ClientAuthMode::Required)?;
        assert!(
            err.contains("the API TLS client CA file is writable by every user (mode 0666)"),
            "{err}"
        );
        // Group-writable and world-readable are allowed: a CA certificate is
        // public, and `root:sipnab 0664` is an ordinary way to hand it over.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o664))?;
        assert!(
            crate::tls_files::client_verifier(path, ClientAuthMode::Required, "API TLS")?.is_some(),
            "a group-writable, world-readable CA file is accepted"
        );
        Ok(())
    }

    /// A client CA file that is missing, or holds no certificate, is refused
    /// naming the file.
    #[test]
    fn a_missing_or_empty_client_ca_is_refused() -> Result<(), TestError> {
        let dir = crate::test_scratch::ScratchDir::new("sipnab-client-ca-")?;
        let absent = dir.join("absent.pem");
        let err = verifier_error(&absent, ClientAuthMode::Required)?;
        assert!(err.contains("absent.pem"), "{err}");
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, "not a certificate\n")?;
        let err = verifier_error(&empty, ClientAuthMode::Optional)?;
        assert!(
            err.contains("empty.pem: no certificate in this file"),
            "{err}"
        );
        Ok(())
    }

    /// `off` builds no verifier and reads no file: the CA is not consulted.
    #[test]
    fn off_builds_no_verifier() -> Result<(), TestError> {
        let dir = crate::test_scratch::ScratchDir::new("sipnab-client-ca-")?;
        let none = crate::tls_files::client_verifier(
            &dir.join("absent.pem"),
            ClientAuthMode::Off,
            "API TLS",
        )?;
        assert!(
            none.is_none(),
            "off builds no verifier, so nothing reads the absent CA file"
        );
        Ok(())
    }

    /// A client CA file holding several CAs accepts a certificate from each
    /// of them, and still refuses one from a CA it does not hold.
    #[tokio::test]
    async fn a_ca_file_with_several_cas_accepts_each() -> Result<(), TestError> {
        let (first, second) = (client_ca("bundle-a")?, client_ca("bundle-b")?);
        let bundle = first.dir.path().join("bundle.pem");
        std::fs::write(&bundle, format!("{}{}", first.pem(), second.pem()))?;
        let served = serve_file(&bundle.to_string_lossy(), ClientAuthMode::Required).await?;
        for (ca, name) in [(&first, "member-a"), (&second, "member-b")] {
            let cert = ca.issue(name, Validity::Current)?;
            assert_eq!(
                ask(&served, Some(&cert)).await?,
                format!("200 127.0.0.1 spiffe://fleet.example.com/member/{name}"),
                "each CA in the file vouches for its own clients"
            );
        }
        let outsider = client_ca("bundle-c")?.issue("member-c", Validity::Current)?;
        assert_refused(
            &ask(&served, Some(&outsider)).await,
            "a third CA's certificate",
        );
        Ok(())
    }

    /// A client whose certificate an intermediate CA issued is served when
    /// it sends the intermediate with its certificate and the CA file holds
    /// only the root.
    #[tokio::test]
    async fn a_chain_through_an_intermediate_is_served() -> Result<(), TestError> {
        let root = client_ca("chain-root")?;
        let member = root
            .intermediate("chain-mid")?
            .issue("member-8", Validity::Current)?;
        let served = serve(&root, ClientAuthMode::Required).await?;
        assert_eq!(
            ask(&served, Some(&member)).await?,
            "200 127.0.0.1 spiffe://fleet.example.com/member/member-8",
            "the root vouches for the intermediate the client sent"
        );
        Ok(())
    }

    /// A chain three intermediates deep is served as well.
    #[tokio::test]
    async fn a_chain_three_intermediates_deep_is_served() -> Result<(), TestError> {
        let root = client_ca("deep-root")?;
        let third = root
            .intermediate("deep-1")?
            .intermediate("deep-2")?
            .intermediate("deep-3")?;
        let member = third.issue("member-9", Validity::Current)?;
        assert_eq!(member.chain.len(), 4, "the leaf and three intermediates");
        let served = serve(&root, ClientAuthMode::Required).await?;
        assert_eq!(
            ask(&served, Some(&member)).await?,
            "200 127.0.0.1 spiffe://fleet.example.com/member/member-9",
            "a longer chain to the same root still verifies, and names the client"
        );
        Ok(())
    }

    /// A client that sends its certificate without the intermediate that
    /// issued it is refused: the CA file holds only the root, and sipnab
    /// fetches nothing.
    #[tokio::test]
    async fn a_chain_missing_its_intermediate_is_refused() -> Result<(), TestError> {
        let root = client_ca("gap-root")?;
        let mut member = root
            .intermediate("gap-mid")?
            .issue("member-10", Validity::Current)?;
        member.chain.truncate(1);
        let served = serve(&root, ClientAuthMode::Required).await?;
        assert_refused(
            &ask(&served, Some(&member)).await,
            "a leaf without its intermediate",
        );
        Ok(())
    }

    /// A CA file that holds only an intermediate accepts that
    /// intermediate's clients: the file's certificates are trust anchors,
    /// whether or not they are roots.
    #[tokio::test]
    async fn an_intermediate_alone_in_the_ca_file_is_an_anchor() -> Result<(), TestError> {
        let mid = client_ca("anchor-root")?.intermediate("anchor-mid")?;
        let member = mid.issue("member-11", Validity::Current)?;
        let served = serve(&mid, ClientAuthMode::Required).await?;
        assert_eq!(
            ask(&served, Some(&member)).await?,
            "200 127.0.0.1 spiffe://fleet.example.com/member/member-11",
            "the intermediate in the CA file anchors its own clients, and names the client"
        );
        Ok(())
    }

    /// A self-signed client certificate is refused: it chains to no CA in
    /// the file.
    #[tokio::test]
    async fn a_self_signed_client_certificate_is_refused() -> Result<(), TestError> {
        let ca = client_ca("selfsigned")?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        let own = super::tls_pki::self_signed_client("member-12")?;
        let answer = ask(&served, Some(&own)).await;
        assert_refused(&answer, "a self-signed certificate");
        assert!(
            answer.err().unwrap_or_default().contains("UnknownCA"),
            "the refusal names the unknown issuer"
        );
        Ok(())
    }

    /// The client CA's own certificate is refused as a client certificate:
    /// a CA certificate is not an end entity.
    #[tokio::test]
    async fn the_ca_certificate_itself_is_refused_as_a_client() -> Result<(), TestError> {
        let ca = client_ca("ca-as-client")?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        let posing = ca.as_client();
        let answer = ask(&served, Some(&posing)).await;
        assert!(
            answer
                .as_ref()
                .err()
                .is_some_and(|e| e.starts_with("read:")),
            "the server, not the client, refuses: the handshake reached it: {answer:?}"
        );
        Ok(())
    }

    /// Over TLS 1.2 a handshake without a certificate is refused too, and a
    /// certificate from the CA is served: the rule does not depend on the
    /// protocol version.
    #[tokio::test]
    async fn tls12_refuses_no_certificate_and_serves_a_good_one() -> Result<(), TestError> {
        let ca = client_ca("tls12")?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        assert_refused(
            &ask_with(&served, None, true).await,
            "TLS 1.2 with no certificate",
        );
        let member = ca.issue("member-13", Validity::Current)?;
        assert!(
            ask_with(&served, Some(&member), true)
                .await?
                .starts_with("200 "),
            "TLS 1.2 with a good certificate is served"
        );
        Ok(())
    }

    /// A certificate that expired one second ago is refused.
    #[tokio::test]
    async fn a_certificate_expired_one_second_ago_is_refused() -> Result<(), TestError> {
        let ca = client_ca("just-expired")?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        let end = std::time::SystemTime::now() - Duration::from_secs(1);
        let cert = ca.issue("member-14", Validity::Until(end))?;
        let answer = ask(&served, Some(&cert)).await;
        assert_refused(&answer, "a certificate one second past its end");
        assert!(
            answer
                .err()
                .unwrap_or_default()
                .contains("CertificateExpired"),
            "the refusal is the expiry"
        );
        Ok(())
    }

    /// A certificate that expires a minute from now is still served.
    #[tokio::test]
    async fn a_certificate_a_minute_from_expiry_is_served() -> Result<(), TestError> {
        let ca = client_ca("nearly-expired")?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        let end = std::time::SystemTime::now() + Duration::from_secs(60);
        let cert = ca.issue("member-15", Validity::Until(end))?;
        assert_eq!(
            ask(&served, Some(&cert)).await?,
            "200 127.0.0.1 spiffe://fleet.example.com/member/member-15",
            "a certificate inside its validity period is served, and names the client"
        );
        Ok(())
    }

    /// A plain-HTTP request to a listener that asks for client certificates
    /// gets no HTTP answer.
    #[tokio::test]
    async fn plain_http_to_the_mtls_port_is_not_served() -> Result<(), TestError> {
        let ca = client_ca("plain")?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        let addr = served.addr.clone();
        let text = tokio::task::spawn_blocking(move || {
            super::tls_pki::plain_http_get(&addr, "/whoami", Duration::from_secs(5))
        })
        .await??;
        assert!(
            !text.starts_with("HTTP/1.1 200"),
            "plain HTTP must not be answered on the TLS port: {text}"
        );
        Ok(())
    }

    /// A unicode common name and SANs reach the handler as written: the
    /// subject as UTF-8 text, not as hex.
    #[tokio::test]
    async fn a_unicode_name_is_read_as_text() -> Result<(), TestError> {
        let ca = client_ca("unicode")?;
        let names = super::tls_pki::Names {
            cn: Some("membre-é-東京".to_string()),
            dns: vec!["xn--tokyo-zr6g.example.com".to_string()],
            uris: Vec::new(),
        };
        let cert = ca.issue_named(
            "unicode",
            &names,
            Validity::Current,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        let leaf = cert.chain.first().ok_or("a leaf")?;
        let identity = ClientIdentity::from_leaf(leaf).ok_or("the leaf parses")?;
        assert_eq!(
            identity.subject, "O=sipnab test fleet,CN=membre-é-東京",
            "a UTF8String common name is text"
        );
        let served = serve(&ca, ClientAuthMode::Required).await?;
        assert_eq!(
            ask(&served, Some(&cert)).await?,
            "200 127.0.0.1 xn--tokyo-zr6g.example.com",
            "with no URI SAN the label is the DNS name"
        );
        Ok(())
    }

    /// A certificate with an empty subject and no SAN is served, and names
    /// the client by its empty subject: the handler still sees that a
    /// certificate verified.
    #[tokio::test]
    async fn an_empty_subject_without_a_san_is_served_with_an_empty_name() -> Result<(), TestError>
    {
        let ca = client_ca("anonymous")?;
        let names = super::tls_pki::Names {
            cn: None,
            dns: Vec::new(),
            uris: Vec::new(),
        };
        let cert = ca.issue_named(
            "anonymous",
            &names,
            Validity::Current,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        let served = serve(&ca, ClientAuthMode::Required).await?;
        assert_eq!(
            ask(&served, Some(&cert)).await?,
            "200 127.0.0.1 ",
            "an empty name, not `none`: a certificate did verify"
        );
        Ok(())
    }

    /// Comments and text between the PEM blocks of a CA file are skipped,
    /// as a CA bundle routinely carries them.
    #[tokio::test]
    async fn junk_between_pem_blocks_is_skipped() -> Result<(), TestError> {
        let (first, second) = (client_ca("junk-a")?, client_ca("junk-b")?);
        let bundle = first.dir.path().join("annotated.pem");
        std::fs::write(
            &bundle,
            format!(
                "# client CAs for the fleet\nIssuer: first\n{}\nnot a block\n\n{}trailing text\n",
                first.pem(),
                second.pem()
            ),
        )?;
        let served = serve_file(&bundle.to_string_lossy(), ClientAuthMode::Required).await?;
        let cert = second.issue("member-16", Validity::Current)?;
        assert!(
            ask(&served, Some(&cert)).await?.starts_with("200 "),
            "the second block still loads past the text around it"
        );
        Ok(())
    }

    /// An empty client CA file (zero bytes) is refused naming the file.
    #[test]
    fn an_empty_client_ca_file_is_refused() -> Result<(), TestError> {
        let dir = crate::test_scratch::ScratchDir::new("sipnab-client-ca-")?;
        let empty = dir.join("zero.pem");
        std::fs::write(&empty, "")?;
        let err = verifier_error(&empty, ClientAuthMode::Required)?;
        assert!(
            err.contains("zero.pem: no certificate in this file"),
            "an empty file is no trust store: {err}"
        );
        Ok(())
    }

    /// A CA file whose PEM block is not valid base64 is refused naming the
    /// block.
    #[test]
    fn a_ca_file_with_a_corrupt_block_is_refused() -> Result<(), TestError> {
        let dir = crate::test_scratch::ScratchDir::new("sipnab-client-ca-")?;
        let bad = dir.join("corrupt.pem");
        std::fs::write(
            &bad,
            "-----BEGIN CERTIFICATE-----\nnot*base64!\n-----END CERTIFICATE-----\n",
        )?;
        let err = verifier_error(&bad, ClientAuthMode::Required)?;
        assert!(
            err.contains("PEM block 'CERTIFICATE' is not valid base64"),
            "the corrupt block is named: {err}"
        );
        Ok(())
    }

    /// A CA file whose block decodes but is not a certificate is refused by
    /// rustls, naming the file.
    #[test]
    fn a_ca_file_holding_a_non_certificate_is_refused() -> Result<(), TestError> {
        let dir = crate::test_scratch::ScratchDir::new("sipnab-client-ca-")?;
        let bad = dir.join("garbage.pem");
        std::fs::write(
            &bad,
            "-----BEGIN CERTIFICATE-----\nAAECAwQ=\n-----END CERTIFICATE-----\n",
        )?;
        let err = verifier_error(&bad, ClientAuthMode::Required)?;
        assert!(
            err.contains("garbage.pem: rustls rejected a certificate"),
            "five bytes are not a certificate: {err}"
        );
        Ok(())
    }

    /// A client CA file this user cannot read is refused naming the file.
    /// Skipped as root, who reads any file whatever its mode.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_client_ca_file_is_refused() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt;
        let ca = client_ca("unreadable")?;
        let path = std::path::Path::new(&ca.ca_file);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000))?;
        if std::fs::read(path).is_ok() {
            // Running as root: mode 000 does not stop this user reading.
            return Ok(());
        }
        let err = verifier_error(path, ClientAuthMode::Required)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
        assert!(
            err.contains("unreadable-client-ca.pem"),
            "the unreadable file is named: {err}"
        );
        Ok(())
    }

    /// `off` with a client CA builds no verifier through `https_config`:
    /// the listener asks for nothing, and the CA file is not read (here it
    /// does not exist).
    #[test]
    fn off_with_a_client_ca_reads_no_ca() -> Result<(), TestError> {
        let pki = test_pki("off-ca")?;
        let auth = crate::config::ClientCertAuth {
            ca: Some("/nonexistent/sipnab-client-ca.pem".to_string()),
            mode: Some(ClientAuthMode::Off),
        };
        https_config(
            (
                std::path::Path::new(&pki.cert),
                std::path::Path::new(&pki.key),
            ),
            crate::cli::API_TLS_FLAGS,
            &auth,
            "API TLS",
        )
        .map_err(|e| format!("off must not read the absent CA file: {e:#}"))?;
        Ok(())
    }
}
