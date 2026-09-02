// SPDX-License-Identifier: MIT OR Apache-2.0

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
    /// Stream Control Transmission Protocol. Parsed: `capture::parse`
    /// recognizes IP protocol 132, walks the chunk list, and extracts SIP from
    /// the first complete (B+E) DATA chunk, recovering the real source and
    /// destination ports from the SCTP common header.
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

    /// IANA IP protocol number of the underlying transport.
    ///
    /// TLS and WebSocket are application framings over TCP, so both report
    /// TCP's number (6) — the number identifies the IP-layer transport, not
    /// the SIP framing.
    pub fn ip_proto_number(self) -> u8 {
        match self {
            Self::Udp => 17,
            Self::Tcp | Self::Tls | Self::Ws => 6,
            Self::Sctp => 132,
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
    //! Transport-proto string and IANA-number mapping tests.
    use super::*;

    /// `as_str` and the `Display` impl must yield the same canonical tag for
    /// every transport variant.
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

    /// Each transport reports its IANA IP protocol number, with TLS and WS
    /// (TCP framings) reporting TCP's 6 rather than a tag of their own.
    #[test]
    fn ip_proto_number_maps_to_iana_transport() {
        // The IP sub-protocol number is printed. TLS and WS both ride
        // on TCP, so they report TCP's number (6), never their own tag.
        assert_eq!(TransportProto::Udp.ip_proto_number(), 17);
        assert_eq!(TransportProto::Tcp.ip_proto_number(), 6);
        assert_eq!(TransportProto::Sctp.ip_proto_number(), 132);
        assert_eq!(TransportProto::Tls.ip_proto_number(), 6);
        assert_eq!(TransportProto::Ws.ip_proto_number(), 6);
    }
}
