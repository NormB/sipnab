//! Leaf network vocabulary types shared across layers.
//!
//! `sip/`, `rtp/`, and `security/` all need to talk about transports, but
//! must not depend on `capture/` (which itself depends on them for payload
//! classification). Types here have no dependencies on any other sipnab
//! module, breaking that cycle. `capture::parse` re-exports them for
//! backward compatibility.

/// Transport-layer protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportProto {
    /// User Datagram Protocol.
    Udp,
    /// Transmission Control Protocol.
    Tcp,
    /// Stream Control Transmission Protocol (stub for future use).
    Sctp,
    /// TLS-encrypted TCP.
    Tls,
    /// WebSocket (SIP over WS).
    Ws,
}

impl TransportProto {
    /// Return the canonical string representation without allocating.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Sctp => "SCTP",
            Self::Tls => "TLS",
            Self::Ws => "WS",
        }
    }
}

impl std::fmt::Display for TransportProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_and_display_agree() {
        for (proto, s) in [
            (TransportProto::Udp, "UDP"),
            (TransportProto::Tcp, "TCP"),
            (TransportProto::Sctp, "SCTP"),
            (TransportProto::Tls, "TLS"),
            (TransportProto::Ws, "WS"),
        ] {
            assert_eq!(proto.as_str(), s);
            assert_eq!(proto.to_string(), s);
        }
    }
}
