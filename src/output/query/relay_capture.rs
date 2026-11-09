// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What this capture saw on one relay socket, for one call: the join every
//! surface that sets a relay's count beside the capture's uses.
//!
//! A relay socket is an address and port the relay allocated to one call.
//! rtpengine hands its ports out again from its range once a call ends, so in
//! a capture longer than one call the same socket can have carried several
//! calls' media. A count of every stream on the socket would set the relay's
//! number for THIS call beside the capture's number for every call that used
//! the port. [`captured_on`] therefore counts:
//!
//! - `linked`: streams on the socket linked to the asked Call-ID, the same
//!   link [`crate::rtp::stream_store::StreamStore::streams_for`] reads;
//! - `unlinked`: streams on the socket linked to no dialog, kept apart and
//!   never added to `linked`, because nothing ties them to this call;
//!
//! and leaves out every stream linked to another Call-ID.
//!
//! The relay's answer carries no call incarnation (`created`) that sipnab
//! parses yet, so the join cannot tell an unlinked stream of this call from
//! an unlinked stream of an earlier call on the same port. That is why
//! `unlinked` is its own number with its own label.

use crate::rtp::stream::RtpStream;

/// Which way across a relay socket a capture count is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Way {
    /// Packets the capture saw sent TO the relay socket.
    ToRelay,
    /// Packets the capture saw sent FROM it.
    FromRelay,
}

/// What the capture saw on one relay socket, one way, for one call.
///
/// Each count is `None` when the capture holds no such stream, which is "not
/// captured", never a measured 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SocketCapture {
    /// Packets in the streams on the socket linked to the asked Call-ID.
    pub linked: Option<u64>,
    /// Packets in the streams on the socket linked to no dialog.
    pub unlinked: Option<u64>,
}

/// Count what `streams` hold on the relay socket `addr:port`, one `way`, for
/// `call_id`.
///
/// A stream counts when its destination (`ToRelay`) or source (`FromRelay`)
/// is the socket. Linked to `call_id`, it adds to `linked`; linked to no
/// dialog, to `unlinked`; linked to another Call-ID, to nothing. An `addr`
/// that is not an IP address matches nothing.
#[must_use]
pub fn captured_on<'a, I>(
    streams: I,
    call_id: &str,
    addr: &str,
    port: u16,
    way: Way,
) -> SocketCapture
where
    I: IntoIterator<Item = &'a RtpStream>,
{
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return SocketCapture::default();
    };
    let want = std::net::SocketAddr::new(ip, port);
    let add = |slot: &mut Option<u64>, n: u64| {
        *slot = Some(slot.unwrap_or(0).saturating_add(n));
    };
    let mut out = SocketCapture::default();
    for s in streams {
        let at = match way {
            Way::ToRelay => s.key.dst,
            Way::FromRelay => s.key.src,
        };
        if at != want {
            continue;
        }
        match s.associated_dialog.as_deref() {
            Some(linked) if linked == call_id => add(&mut out.linked, s.packet_count),
            Some(_) => {}
            None => add(&mut out.unlinked, s.packet_count),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::StreamKey;
    use chrono::{DateTime, TimeDelta, Utc};

    type TestError = Box<dyn std::error::Error>;

    const CALL: &str = "a@example.invalid";
    const OTHER: &str = "b@example.invalid";
    const RELAY: &str = "192.0.2.11";

    fn at(ms: i64) -> DateTime<Utc> {
        DateTime::UNIX_EPOCH + TimeDelta::seconds(1_700_000_000) + TimeDelta::milliseconds(ms)
    }

    /// One stream from `src` to `dst` with `packets` packets, linked to
    /// `call`, first seen at `ms`.
    fn stream(
        ssrc: u32,
        src: &str,
        dst: &str,
        packets: u64,
        call: Option<&str>,
        ms: i64,
    ) -> Result<RtpStream, TestError> {
        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 160,
            ssrc,
            payload_offset: 12,
        };
        let mut s = RtpStream::new(
            StreamKey::new(ssrc, src.parse()?, dst.parse()?),
            &header,
            at(ms),
        );
        s.packet_count = packets;
        s.associated_dialog = call.map(str::to_string);
        Ok(s)
    }

    /// A stream to the relay socket linked to the call is counted.
    #[test]
    fn a_linked_stream_to_the_socket_is_counted() -> Result<(), TestError> {
        let s = [stream(
            1,
            "198.51.100.5:4000",
            "192.0.2.11:30000",
            250,
            Some(CALL),
            0,
        )?];
        let c = captured_on(&s, CALL, RELAY, 30000, Way::ToRelay);
        assert_eq!(
            c.linked,
            Some(250),
            "A stream to the relay socket linked to the call is counted"
        );
        assert_eq!(
            c.unlinked, None,
            "A stream to the relay socket linked to the call is counted"
        );
        Ok(())
    }

    /// `FromRelay` reads the stream's source, not its destination.
    #[test]
    fn from_the_relay_reads_the_source() -> Result<(), TestError> {
        let s = [stream(
            1,
            "192.0.2.11:30000",
            "198.51.100.5:4000",
            90,
            Some(CALL),
            0,
        )?];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::FromRelay).linked,
            Some(90),
            "`FromRelay` reads the stream's source, not its destination"
        );
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay),
            SocketCapture::default(),
            "a stream FROM the socket is not one TO it"
        );
        Ok(())
    }

    /// Two streams of the call on one socket (an SSRC change) add up.
    #[test]
    fn two_streams_of_the_call_on_one_socket_add_up() -> Result<(), TestError> {
        let s = [
            stream(
                1,
                "198.51.100.5:4000",
                "192.0.2.11:30000",
                100,
                Some(CALL),
                0,
            )?,
            stream(
                2,
                "198.51.100.5:4000",
                "192.0.2.11:30000",
                40,
                Some(CALL),
                2000,
            )?,
        ];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay).linked,
            Some(140),
            "Two streams of the call on one socket (an SSRC change) add up"
        );
        Ok(())
    }

    /// A stream linked to ANOTHER call on the same relay port is not this
    /// call's: rtpengine reuses ports.
    #[test]
    fn another_calls_stream_on_a_reused_port_is_left_out() -> Result<(), TestError> {
        let s = [
            stream(
                1,
                "198.51.100.5:4000",
                "192.0.2.11:30000",
                3000,
                Some(OTHER),
                0,
            )?,
            stream(
                2,
                "198.51.100.6:4000",
                "192.0.2.11:30000",
                250,
                Some(CALL),
                60_000,
            )?,
        ];
        let c = captured_on(&s, CALL, RELAY, 30000, Way::ToRelay);
        assert_eq!(c.linked, Some(250), "only the asked call's packets");
        assert_eq!(c.unlinked, None, "another call's stream is not unlinked");
        Ok(())
    }

    /// Only another call used the port: this call was not captured there.
    #[test]
    fn only_another_call_on_the_port_reads_not_captured() -> Result<(), TestError> {
        let s = [stream(
            1,
            "198.51.100.5:4000",
            "192.0.2.11:30000",
            3000,
            Some(OTHER),
            0,
        )?];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay),
            SocketCapture::default(),
            "Only another call used the port: this call was not captured there"
        );
        Ok(())
    }

    /// A stream linked to no dialog is reported apart, never in `linked`.
    #[test]
    fn an_unlinked_stream_is_reported_apart() -> Result<(), TestError> {
        let s = [stream(
            1,
            "198.51.100.5:4000",
            "192.0.2.11:30000",
            75,
            None,
            0,
        )?];
        let c = captured_on(&s, CALL, RELAY, 30000, Way::ToRelay);
        assert_eq!(
            c.linked, None,
            "A stream linked to no dialog is reported apart, never in `linked`"
        );
        assert_eq!(
            c.unlinked,
            Some(75),
            "A stream linked to no dialog is reported apart, never in `linked`"
        );
        Ok(())
    }

    /// Linked and unlinked on one socket keep their own counts.
    #[test]
    fn linked_and_unlinked_are_never_added_together() -> Result<(), TestError> {
        let s = [
            stream(
                1,
                "198.51.100.5:4000",
                "192.0.2.11:30000",
                200,
                Some(CALL),
                0,
            )?,
            stream(2, "198.51.100.7:4000", "192.0.2.11:30000", 30, None, 500)?,
        ];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay),
            SocketCapture {
                linked: Some(200),
                unlinked: Some(30)
            },
            "Linked and unlinked on one socket keep their own counts"
        );
        Ok(())
    }

    /// Another port on the relay's address is another socket.
    #[test]
    fn another_port_is_another_socket() -> Result<(), TestError> {
        let s = [stream(
            1,
            "198.51.100.5:4000",
            "192.0.2.11:30002",
            10,
            Some(CALL),
            0,
        )?];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay),
            SocketCapture::default(),
            "Another port on the relay's address is another socket"
        );
        Ok(())
    }

    /// The same port on another address is another socket.
    #[test]
    fn another_address_is_another_socket() -> Result<(), TestError> {
        let s = [stream(
            1,
            "198.51.100.5:4000",
            "192.0.2.12:30000",
            10,
            Some(CALL),
            0,
        )?];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay),
            SocketCapture::default(),
            "The same port on another address is another socket"
        );
        Ok(())
    }

    /// An address the relay wrote that is not an IP address matches nothing.
    #[test]
    fn an_address_that_does_not_parse_matches_nothing() -> Result<(), TestError> {
        let s = [stream(
            1,
            "198.51.100.5:4000",
            "192.0.2.11:30000",
            10,
            Some(CALL),
            0,
        )?];
        for addr in ["", "relay.example.com", "192.0.2.11:30000"] {
            assert_eq!(
                captured_on(&s, CALL, addr, 30000, Way::ToRelay),
                SocketCapture::default(),
                "{addr:?}"
            );
        }
        Ok(())
    }

    /// An IPv6 relay socket joins the same way.
    #[test]
    fn an_ipv6_socket_joins() -> Result<(), TestError> {
        let s = [
            stream(
                1,
                "[2001:db8::5]:4000",
                "[2001:db8::11]:30000",
                60,
                Some(CALL),
                0,
            )?,
            stream(
                2,
                "[2001:db8::6]:4000",
                "[2001:db8::11]:30000",
                9,
                Some(OTHER),
                0,
            )?,
        ];
        assert_eq!(
            captured_on(&s, CALL, "2001:db8::11", 30000, Way::ToRelay).linked,
            Some(60),
            "An IPv6 relay socket joins the same way"
        );
        Ok(())
    }

    /// No stream at all is "not captured", not a measured 0.
    #[test]
    fn no_stream_is_not_captured_rather_than_zero() {
        let none: [RtpStream; 0] = [];
        assert_eq!(
            captured_on(&none, CALL, RELAY, 30000, Way::ToRelay),
            SocketCapture {
                linked: None,
                unlinked: None
            },
            "No stream at all is \"not captured\", not a measured 0"
        );
    }

    /// A linked stream that counted 0 packets is a measured 0.
    #[test]
    fn a_linked_stream_of_zero_packets_is_a_measured_zero() -> Result<(), TestError> {
        let s = [stream(
            1,
            "198.51.100.5:4000",
            "192.0.2.11:30000",
            0,
            Some(CALL),
            0,
        )?];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay).linked,
            Some(0),
            "A linked stream that counted 0 packets is a measured 0"
        );
        Ok(())
    }

    /// Two calls that used the port less than a second apart each count only
    /// their own packets.
    #[test]
    fn port_reuse_within_one_second_keeps_each_call_apart() -> Result<(), TestError> {
        let s = [
            stream(
                1,
                "198.51.100.5:4000",
                "192.0.2.11:30000",
                500,
                Some(OTHER),
                0,
            )?,
            stream(
                2,
                "198.51.100.6:4000",
                "192.0.2.11:30000",
                20,
                Some(CALL),
                400,
            )?,
        ];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay).linked,
            Some(20),
            "Two calls that used the port less than a second apart each count only their own packets"
        );
        assert_eq!(
            captured_on(&s, OTHER, RELAY, 30000, Way::ToRelay).linked,
            Some(500),
            "Two calls that used the port less than a second apart each count only their own packets"
        );
        Ok(())
    }

    /// The Call-ID is compared exactly, as SIP compares it.
    #[test]
    fn the_call_id_is_compared_exactly() -> Result<(), TestError> {
        let s = [stream(
            1,
            "198.51.100.5:4000",
            "192.0.2.11:30000",
            5,
            Some("A@example.invalid"),
            0,
        )?];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay),
            SocketCapture::default(),
            "The Call-ID is compared exactly, as SIP compares it"
        );
        Ok(())
    }

    /// A sum that would overflow stops at the largest count.
    #[test]
    fn the_sum_saturates() -> Result<(), TestError> {
        let s = [
            stream(
                1,
                "198.51.100.5:4000",
                "192.0.2.11:30000",
                u64::MAX,
                Some(CALL),
                0,
            )?,
            stream(2, "198.51.100.5:4000", "192.0.2.11:30000", 5, Some(CALL), 0)?,
        ];
        assert_eq!(
            captured_on(&s, CALL, RELAY, 30000, Way::ToRelay).linked,
            Some(u64::MAX),
            "A sum that would overflow stops at the largest count"
        );
        Ok(())
    }
}
