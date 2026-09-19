// SPDX-License-Identifier: MIT OR Apache-2.0

//! An external consumer can use parser argument types and inspect partial parses.

use sipnab::net::TransportProto;
use sipnab::sip::parser::parse_sip_bytes;
use sipnab::{bytes::Bytes, chrono::Utc};

/// The public parser can be called using only types supplied by sipnab.
#[test]
fn consumer_can_distinguish_complete_and_partial_messages() {
    for (payload, partial) in [
        (
            "OPTIONS sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            "OPTIONS sip:bob@example.com SIP/2.0\r\nContent-Length: 10\r\n\r\nx",
            true,
        ),
    ] {
        let message = parse_sip_bytes(
            &Bytes::from_static(payload.as_bytes()),
            Utc::now(),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .unwrap();
        assert_eq!(message.parse_error, partial);
    }
}
