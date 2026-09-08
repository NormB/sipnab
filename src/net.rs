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

    /// The range's own network address — the first address it contains.
    ///
    /// Exposed so a test can assert the parse and the match agree without
    /// reaching into the bit layout: if the mask used to BUILD the network and
    /// the mask used to MATCH against it ever disagree, a range stops
    /// containing its own network address, and that is the shape the
    /// disagreement takes.
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
}

/// Whether an address is one the public internet does not route to.
///
/// RFC 1918 space, IPv4 link-local, IPv6 unique-local (`fc00::/7`) and IPv6
/// link-local (`fe80::/10`). Loopback is deliberately NOT here — see
/// [`is_unroutable_publicly`], which adds it — because the two callers that
/// existed before this function disagreed about loopback on purpose and
/// unifying them would have changed one of their answers.
///
/// **Carrier-grade NAT space (`100.64.0.0/10`) is deliberately excluded.** It
/// is routable within the carrier that assigned it, and a large share of
/// working mobile traffic arrives from it, so treating it as private would
/// fire on calls that are fine.
///
/// One rule in one place: this was written twice, in `rtp::diagnosis` and in
/// `security::recommend`, and a third copy was about to be written for the
/// registration contact check.
#[must_use]
pub fn is_private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        // `is_unique_local` and `is_unicast_link_local` are still unstable on
        // the pinned toolchain, so the two prefixes are matched directly.
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80
        }
    }
}

/// [`is_private_address`], plus loopback.
///
/// The reading the media diagnosis wants: an address that cannot be reached
/// from outside the host at all is as undeliverable as one that cannot be
/// reached from outside the site.
#[must_use]
pub fn is_unroutable_publicly(ip: IpAddr) -> bool {
    is_private_address(ip) || ip.is_loopback()
}

/// Format an endpoint so it can be read back as an address.
///
/// `{ip}:{port}` is ambiguous for IPv6: an endpoint renders as
/// `2001:db8::1:5060`, which no parser can split back into an address and a
/// port, and which a reader cannot tell from an address that simply ends in
/// `:5060`. RFC 3986 section 3.2.2 gives the bracketed form for exactly this
/// reason, and `SocketAddr`'s own `Display` uses it.
///
/// This string is the participant IDENTITY in an exported sequence diagram,
/// so an ambiguous one is not only unreadable — two distinct endpoints can
/// render alike and merge into one lifeline.
///
/// # Arguments
/// * `ip` — the endpoint address.
/// * `port` — its port.
#[must_use]
pub fn endpoint_label(ip: std::net::IpAddr, port: u16) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
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
    /// An IPv6 endpoint is bracketed, so it can be read back.
    ///
    /// MER5. `{ip}:{port}` renders `2001:db8::1` on port 5060 as
    /// `2001:db8::1:5060`, which no parser can split and which a reader cannot
    /// tell from an address ending in `:5060`. In an exported diagram this
    /// string is the participant IDENTITY, so an ambiguous one can merge two
    /// distinct endpoints onto one lifeline.
    #[test]
    fn an_ipv6_endpoint_is_bracketed() {
        let v6: std::net::IpAddr = "2001:db8::1".parse().expect("literal");
        assert_eq!(endpoint_label(v6, 5060), "[2001:db8::1]:5060");
    }

    /// The bracketed form round-trips through `SocketAddr`.
    ///
    /// The property that makes it unambiguous, asserted rather than asserted
    /// about: if the standard library can parse it back, so can a reader.
    #[test]
    fn every_endpoint_label_parses_back_to_itself() {
        for (ip, port) in [
            ("198.51.100.7", 5060u16),
            ("2001:db8::1", 5060),
            ("2001:db8:0:0:0:0:0:1", 5061),
            ("::1", 1),
            ("::ffff:198.51.100.7", 5060),
        ] {
            let addr: std::net::IpAddr = ip.parse().expect("literal");
            let label = endpoint_label(addr, port);
            let parsed: std::net::SocketAddr = label
                .parse()
                .unwrap_or_else(|e| panic!("{label} does not parse back: {e}"));
            assert_eq!(parsed.ip(), addr, "{label}");
            assert_eq!(parsed.port(), port, "{label}");
        }
    }

    /// IPv4 is not bracketed, because it never needed to be.
    #[test]
    fn an_ipv4_endpoint_is_not_bracketed() {
        let v4: std::net::IpAddr = "198.51.100.7".parse().expect("literal");
        assert_eq!(endpoint_label(v4, 5060), "198.51.100.7:5060");
    }

    /// Two IPv6 endpoints that differ only in their zero-run stay distinct.
    ///
    /// The collision this prevents: the old id derivation mapped both `:` and
    /// `.` to `_`, so two spellings of one address — and two DIFFERENT
    /// addresses — could land on the same identifier and merge into one
    /// lifeline. `Display` canonicalizes the spelling, and brackets keep the
    /// port from blurring into the address.
    #[test]
    fn distinct_ipv6_endpoints_do_not_collide() {
        let a: std::net::IpAddr = "2001:db8::1".parse().expect("literal");
        let b: std::net::IpAddr = "2001:db8::2".parse().expect("literal");
        assert_ne!(endpoint_label(a, 5060), endpoint_label(b, 5060));
        // Same address, two spellings: one label, so they are ONE lifeline.
        let spelled: std::net::IpAddr = "2001:0db8:0000::0001".parse().expect("literal");
        assert_eq!(endpoint_label(a, 5060), endpoint_label(spelled, 5060));
    }
}
