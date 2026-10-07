// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pairing rtpproxy's commands with their replies, so a capture can name the
//! relay's media (RP-WIRE).
//!
//! Written before the behavior exists. rtpproxy's control protocol splits what
//! sipnab needs across two datagrams: the COMMAND names the call and the REPLY
//! names the port the relay opened. Observed against the lab relay (rtpproxy
//! 3.2.0) on 2026-09-28:
//!
//! ```text
//! p2 U rpwire-probe-1 192.0.2.10 40000 ftag1  ->  p2 49514 10.0.0.40
//! p3 D rpwire-probe-1 ftag1                   ->  p3 0
//! ```
//!
//! Only the cookie joins the two, so each rule below is about what may and may
//! not be joined by it.

#![cfg(feature = "full")]

use std::net::{IpAddr, Ipv4Addr};

use sipnab::relay::reconcile::RelayLink;
use sipnab::relay::rtpproxy::{Pairing, decode_command, decode_reply};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

fn command(text: &str) -> Result<sipnab::relay::rtpproxy::RtpproxyControl, TestError> {
    Ok(decode_command(text.as_bytes()).ok_or_else(|| format!("fixture must decode: {text:?}"))?)
}

fn reply(text: &str) -> Result<sipnab::relay::rtpproxy::RtpproxyControl, TestError> {
    Ok(decode_reply(text.as_bytes()).ok_or_else(|| format!("fixture must decode: {text:?}"))?)
}

fn lab_endpoint(call_id: &str) -> RelayLink {
    RelayLink {
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 40)),
        port: 49514,
        call_id: call_id.to_string(),
    }
}

#[test]
fn an_update_and_its_reply_name_the_relays_media_for_the_call() -> Result<(), TestError> {
    let mut p = Pairing::new(16);
    assert_eq!(
        p.observe(command("p2 U rpwire-probe-1 192.0.2.10 40000 ftag1\n")?),
        None,
        "a command alone names no port"
    );
    assert_eq!(
        p.observe(reply("p2 49514 10.0.0.40\n")?),
        Some(lab_endpoint("rpwire-probe-1"))
    );
    assert_eq!(p.pending(), 0, "a paired command is done with");
    Ok(())
}

#[test]
fn a_lookup_and_its_reply_name_the_relays_media_too() -> Result<(), TestError> {
    let mut p = Pairing::new(16);
    p.observe(command(
        "q1 L rpwire-probe-1 192.0.2.20 40002 ftag1 ttag1\n",
    )?);
    assert_eq!(
        p.observe(reply("q1 49514 10.0.0.40\n")?),
        Some(lab_endpoint("rpwire-probe-1"))
    );
    Ok(())
}

#[test]
fn a_reply_nobody_asked_for_names_nothing() -> Result<(), TestError> {
    let mut p = Pairing::new(16);
    assert_eq!(p.observe(reply("p2 49514 10.0.0.40\n")?), None);
    assert_eq!(p.pending(), 0);
    Ok(())
}

#[test]
fn a_reply_to_another_cookie_names_nothing_and_leaves_the_command_waiting() -> Result<(), TestError>
{
    let mut p = Pairing::new(16);
    p.observe(command("p2 U rpwire-probe-1 192.0.2.10 40000 ftag1\n")?);
    assert_eq!(p.observe(reply("zz 49514 10.0.0.40\n")?), None);
    assert_eq!(p.pending(), 1);
    assert_eq!(
        p.observe(reply("p2 49514 10.0.0.40\n")?),
        Some(lab_endpoint("rpwire-probe-1")),
        "its own reply still pairs"
    );
    Ok(())
}

#[test]
fn recording_streams_are_never_named_as_the_calls_media() -> Result<(), TestError> {
    // `R` and `C` open recording or copy streams. Naming one as the call's
    // media would put a party in the call that the call never had.
    // `C` names where the copy goes before the tag, per rtpproxy's argument
    // counts (3-4 tokens for `R`, 4-5 for `C`).
    for (verb, args) in [
        ("R", "rpwire-probe-1 ftag1"),
        ("C", "rpwire-probe-1 copy.rtp ftag1"),
    ] {
        let mut p = Pairing::new(16);
        p.observe(command(&format!("r1 {verb} {args}\n"))?);
        assert_eq!(p.observe(reply("r1 49514 10.0.0.40\n")?), None, "{verb}");
        assert_eq!(p.pending(), 0, "{verb}: its reply still clears it");
    }
    Ok(())
}

#[test]
fn a_refusal_names_nothing_and_clears_the_command() -> Result<(), TestError> {
    let mut p = Pairing::new(16);
    p.observe(command("e1 U rpwire-probe-1 192.0.2.10 40000 ftag1\n")?);
    assert_eq!(p.observe(reply("e1 E50\n")?), None);
    assert_eq!(p.pending(), 0);
    Ok(())
}

#[test]
fn commands_that_open_nothing_pair_to_nothing() -> Result<(), TestError> {
    let mut p = Pairing::new(16);
    p.observe(command("p3 D rpwire-probe-1 ftag1\n")?);
    p.observe(command("p1 V\n")?);
    assert_eq!(p.observe(reply("p3 0\n")?), None);
    assert_eq!(p.observe(reply("p1 20040107\n")?), None);
    assert_eq!(p.pending(), 0);
    Ok(())
}

#[test]
fn a_retried_command_names_the_same_media_once_per_reply_and_leaves_nothing_behind()
-> Result<(), TestError> {
    // RP4. rtpproxy answers a retransmitted command from its reply cache, so
    // one cookie is seen twice in each direction. Whatever order the four
    // datagrams arrive in, every name produced is the same endpoint and the
    // table is empty afterwards.
    let cmd = "p2 U rpwire-probe-1 192.0.2.10 40000 ftag1\n";
    let rep = "p2 49514 10.0.0.40\n";
    for order in [[cmd, cmd, rep, rep], [cmd, rep, cmd, rep]] {
        let mut p = Pairing::new(16);
        let mut named = Vec::new();
        for (i, datagram) in order.iter().enumerate() {
            let control = if *datagram == cmd {
                command(datagram)?
            } else {
                reply(datagram)?
            };
            if let Some(endpoint) = p.observe(control) {
                named.push((i, endpoint));
            }
        }
        assert!(!named.is_empty(), "{order:?}");
        assert!(
            named
                .iter()
                .all(|(_, e)| *e == lab_endpoint("rpwire-probe-1")),
            "{order:?}: {named:?}"
        );
        assert_eq!(p.pending(), 0, "{order:?}");
    }
    Ok(())
}

#[test]
fn unanswered_commands_are_bounded_and_the_oldest_go_first() -> Result<(), TestError> {
    // A relay that never answers, or a capture that saw only one direction,
    // must not grow the table without limit.
    let mut p = Pairing::new(4);
    for i in 0..10 {
        p.observe(command(&format!(
            "k{i} U call-{i} 192.0.2.10 40000 ftag\n"
        ))?);
    }
    assert_eq!(p.pending(), 4);
    assert_eq!(p.observe(reply("k0 49514 10.0.0.40\n")?), None, "evicted");
    assert_eq!(
        p.observe(reply("k9 49514 10.0.0.40\n")?),
        Some(lab_endpoint("call-9")),
        "kept"
    );
    Ok(())
}

#[test]
fn a_reply_address_that_is_not_an_ip_address_names_nothing() -> Result<(), TestError> {
    // The endpoint is matched against packets, which carry addresses. A name
    // would have to be resolved, and resolving what a sniffed datagram says
    // is a lookup on an attacker's behalf.
    let mut p = Pairing::new(16);
    p.observe(command("h1 U rpwire-probe-1 192.0.2.10 40000 ftag1\n")?);
    assert_eq!(p.observe(reply("h1 49514 relay.example\n")?), None);
    assert_eq!(p.pending(), 0);
    Ok(())
}
