// SPDX-License-Identifier: MIT OR Apache-2.0

//! A loopback TCP port where a connection is refused, held for as long as a
//! test needs it.
//!
//! The obvious way to find such a port is to bind `127.0.0.1:0`, read the
//! number, and release the socket. Between the release and the connect, any
//! test running alongside that binds `:0` can be handed the same number and
//! listen on it; the "refused" premise then fails, and the test either fails
//! or passes for the wrong reason. A parallel test once took a released HEP
//! port the same way.
//!
//! [`refused_tcp_port`] keeps the socket BOUND and never calls `listen`.
//! Linux answers a SYN to a bound, non-listening socket with a reset, so the
//! connect fails with `ConnectionRefused`; the socket sets neither
//! `SO_REUSEADDR` nor `SO_REUSEPORT`, so no other socket can bind the number
//! while the guard lives. `std` cannot do this (`TcpListener::bind` always
//! listens), which is why it uses `socket2`.
#![allow(dead_code)]

use std::net::SocketAddr;

use socket2::{Domain, Socket, Type};

/// The error a fallible helper here returns.
pub type TestError = Box<dyn std::error::Error>;

/// A TCP port on `127.0.0.1` that refuses connections while this value lives.
///
/// Hold it for the whole test body: dropping it releases the number.
pub struct RefusedPort {
    _socket: Socket,
    addr: SocketAddr,
}

impl RefusedPort {
    /// The port number.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// `127.0.0.1:<port>`.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// A loopback TCP port that refuses connections, held until the returned
/// guard is dropped.
pub fn refused_tcp_port() -> Result<RefusedPort, TestError> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())?;
    let addr = socket
        .local_addr()?
        .as_socket()
        .ok_or("a bound IPv4 socket has an IP address")?;
    Ok(RefusedPort {
        _socket: socket,
        addr,
    })
}
