// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Telephone events at a dynamic payload type, sharing an SSRC with the audio.
//!
//! [RFC 4733 section 7.1.1](https://www.rfc-editor.org/rfc/rfc4733.html#section-7.1.1)
//! registers `telephone-event` with no static payload type: the number is
//! whatever the SDP bound with `a=rtpmap:<pt> telephone-event/<rate>`, from
//! the dynamic range 96-127 of
//! [RFC 3551 section 6](https://www.rfc-editor.org/rfc/rfc3551.html#section-6).
//!
//! `tests/pcap-samples/SIP_DTMF2.cap` negotiates it as
//! `a=rtpmap:96 telephone-event/8000` and sends the events on the same SSRC
//! as its PCMA audio. sipnab read the stream's codec as PCMA, so it looked for
//! telephone events at PT 101 and decoded none of the seven keys the capture
//! carries.
#![cfg(feature = "native")]

#[path = "support/run.rs"]
mod run_support;

/// The error a test returns: any error, boxed, so `?` works on I/O and
/// assertion failures alike.
type TestError = Box<dyn std::error::Error>;

/// The capture under test.
const CAPTURE: &str = "tests/pcap-samples/SIP_DTMF2.cap";

/// The keys the capture's RTP carries, in order: event codes 6, 7, 8, 9, 1,
/// 2 and 3, each in one end packet with duration 960 (120 ms at 8000 Hz).
const KEYS: [&str; 7] = ["6", "7", "8", "9", "1", "2", "3"];

/// The digit of every `DTMF cleartext` log message, in the order logged.
fn cleartext_digits(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter_map(|line| line.split_once("DTMF cleartext digit='"))
        .filter_map(|(_, rest)| rest.split_once('\'').map(|(digit, _)| digit.to_owned()))
        .collect()
}

/// Every key in the capture is decoded once, in order, from PT 96.
#[test]
fn every_key_at_the_negotiated_dynamic_payload_type_is_decoded() -> Result<(), TestError> {
    let (_stdout, stderr, code) = run_support::run(
        &["-N", "-I", CAPTURE, "--no-config", "-t", "--dtmf-cleartext"],
        Some("debug"),
    )?;
    assert_eq!(code, Some(0), "sipnab exited {code:?}\nstderr:\n{stderr}");
    let masked = stderr
        .lines()
        .filter(|line| line.contains("DTMF digit="))
        .count();
    assert_eq!(masked, KEYS.len(), "one masked line per key\n{stderr}");
    assert_eq!(cleartext_digits(&stderr), KEYS, "the keys, in order");
    Ok(())
}
