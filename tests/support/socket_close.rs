// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Closing a test's socket so that the peer sees the close at once.
//!
//! Dropping a socket closes this process's descriptor for it, not the
//! socket. A child process that another test is starting at that moment
//! holds a copy of every descriptor this process has open, from the moment
//! the child is created until it executes its program, when close-on-exec
//! closes the copies. While a copy lives, a dropped listener keeps
//! listening and a dropped connection stays open: the peer sees nothing.
//!
//! Under load that window is long enough to matter. A listener that was
//! dropped and replaced kept taking about half of the new connections, and
//! `hep_send_replays_to_a_collector_that_went_away` failed about once in a
//! hundred runs beside the rest of the suite.
//!
//! `shutdown` acts on the socket itself, whatever descriptors refer to it, so
//! each function here shuts the socket down and then drops it. On Linux a
//! shut-down listener stops listening at once. Elsewhere `shutdown` on a
//! listener is refused, the error is ignored, and the drop is all that
//! happens, as before.
#![allow(dead_code)]

use std::net::{Shutdown, TcpListener, TcpStream};

/// Stop `listener` listening now, then drop it.
pub fn close_listener(listener: TcpListener) {
    let _ = socket2::SockRef::from(&listener).shutdown(Shutdown::Both);
    drop(listener);
}

/// Close `stream` in both directions now, so the peer reads an end of
/// stream, then drop it.
pub fn close_stream(stream: TcpStream) {
    let _ = stream.shutdown(Shutdown::Both);
    drop(stream);
}
