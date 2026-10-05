// SPDX-License-Identifier: MIT OR Apache-2.0

//! The HTTPS listener shared by the servers built on axum: the REST API
//! (`--api-tls-cert`) and MCP over HTTP (`--mcp-tls-cert`).
//!
//! One accept loop, one handshake timeout and one cap on handshakes in
//! progress, so the two cannot drift apart on how they treat a slow or
//! hostile client. The certificate and key are read by
//! [`crate::tls_files::server_config`], which the metrics endpoint and the
//! HEP listener share too.

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
                    // The slot is held until axum has the connection, so a
                    // backlog of finished handshakes counts against the cap.
                    let _ = ready.send((stream, peer)).await;
                }
                Ok(Err(e)) => tracing::debug!("{surface} handshake with {peer} failed: {e}"),
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
