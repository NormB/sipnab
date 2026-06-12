#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::parse::TransportProto;
use sipnab::sip::parser::parse_sip;
use std::net::IpAddr;

fuzz_target!(|data: &[u8]| {
    let _ = parse_sip(
        data,
        chrono::Utc::now(),
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        5060,
        5060,
        TransportProto::Udp,
    );
});
