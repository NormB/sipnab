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

use std::net::IpAddr;

/// A parsed CIDR range for IP allowlisting.
#[derive(Debug, Clone)]
pub struct CidrRange {
    /// Network address (masked).
    network: u128,
    /// Number of prefix bits.
    prefix_len: u8,
    /// Whether this is an IPv4 or IPv6 range.
    is_v4: bool,
}

impl CidrRange {
    /// Parse a CIDR string like "10.0.0.0/8" or "2001:db8::/32".
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidCidr`] if the notation is invalid.
    pub fn parse(cidr: &str) -> Result<Self, crate::Error> {
        Self::parse_inner(cidr).map_err(|reason| crate::Error::InvalidCidr {
            input: cidr.to_string(),
            reason,
        })
    }

    /// Parse implementation: split `cidr` at `/`, parse the address and
    /// prefix length, and normalize to a masked 128-bit network value
    /// (IPv4 occupies the top 32 bits). Returns the range or a plain-text
    /// reason string for `CidrRange::parse` to wrap.
    fn parse_inner(cidr: &str) -> Result<Self, String> {
        // A bare address is a HOST, so `--hep-allow 10.0.0.40` means what an
        // operator plainly intends without their having to know to write
        // `/32`. Note which way this defaults: a host route is the NARROWEST
        // reading, so a missing prefix can only ever admit less. Inferring a
        // classful network from `10.0.0.0` would silently admit sixteen
        // million addresses nobody named, which is the opposite of what an
        // allowlist is for.
        let (addr_str, prefix_str) = match cidr.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (cidr, None),
        };

        let addr: IpAddr = addr_str.parse().map_err(|e| format!("invalid IP: {e}"))?;

        let (ip_bits, is_v4, max_prefix) = match addr {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4) as u128;
                (bits << 96, true, 32u8)
            }
            IpAddr::V6(v6) => (u128::from(v6), false, 128u8),
        };

        let prefix_len: u8 = match prefix_str {
            Some(p) => p
                .parse()
                .map_err(|e| format!("invalid prefix length: {e}"))?,
            // Full width for the family: one host, and only that host.
            None => max_prefix,
        };

        if prefix_len > max_prefix {
            return Err(format!(
                "prefix length {prefix_len} exceeds maximum {max_prefix} for '{cidr}'"
            ));
        }

        let mask = if prefix_len == 0 {
            0u128
        } else if is_v4 {
            let shift = 32 - prefix_len;
            ((u32::MAX << shift) as u128) << 96
        } else {
            u128::MAX << (128 - prefix_len)
        };

        Ok(Self {
            network: ip_bits & mask,
            prefix_len,
            is_v4,
        })
    }

    /// Check whether an IP address falls within this CIDR range.
    ///
    /// Returns `false` for an address-family mismatch (an IPv4 range never
    /// contains a genuine IPv6 address, and vice versa) — with one exception
    /// that is not a mismatch at all.
    ///
    /// **An IPv4-mapped IPv6 address is matched against an IPv4 range.** A
    /// listener bound to `[::]` accepts IPv4 connections on Linux, and the
    /// kernel reports those peers as `::ffff:a.b.c.d`. An operator who wrote
    /// `--hep-allow 198.51.100.0/24` named a host, not a socket family, and before
    /// this every legitimate agent reaching a dual-stack listener was refused.
    /// That is the strict direction, but it does not end safely: an allowlist
    /// that refuses everyone gets widened or switched off, and SN-01 pushes
    /// operators toward exactly this pairing by requiring an allowlist for any
    /// non-loopback bind.
    ///
    /// A range written in the mapped form itself stays IPv6 and keeps matching
    /// as one, so an operator who deliberately wrote `::ffff:0:0/96` gets what
    /// The range's own network address — the first address it contains.
    ///
    /// Exposed so a test can assert the parse and the match agree without
    /// reaching into the bit layout: if the mask used to BUILD the network and
    /// the mask used to MATCH against it ever disagree, a range stops
    /// containing its own network address, and that is the shape the disagreement
    /// takes.
    #[must_use]
    pub fn network_addr(&self) -> IpAddr {
        if self.is_v4 {
            IpAddr::V4(std::net::Ipv4Addr::from(
                ((self.network >> 96) & 0xFFFF_FFFF) as u32,
            ))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::from(self.network))
        }
    }

    /// they asked for.
    pub fn contains(&self, addr: IpAddr) -> bool {
        let ip_bits = match addr {
            IpAddr::V4(v4) => {
                if !self.is_v4 {
                    return false;
                }
                (u32::from(v4) as u128) << 96
            }
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                // The same host, arriving over a dual-stack socket.
                Some(v4) if self.is_v4 => (u32::from(v4) as u128) << 96,
                _ => {
                    if self.is_v4 {
                        return false;
                    }
                    u128::from(v6)
                }
            },
        };

        let max_prefix = if self.is_v4 { 32u8 } else { 128u8 };
        let mask = if self.prefix_len == 0 {
            0u128
        } else if self.is_v4 {
            let shift = 32 - self.prefix_len;
            ((u32::MAX << shift) as u128) << 96
        } else {
            u128::MAX << (max_prefix - self.prefix_len)
        };

        (ip_bits & mask) == self.network
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
