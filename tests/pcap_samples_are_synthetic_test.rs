// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generated sample captures must stay free of anything identifying.
//!
//! Thirteen fixtures under `tests/pcap-samples/` are written by
//! `tests/gen-pcap-samples.py` and `tests/gen-link-type-samples.py` precisely
//! so that their provenance is a reviewable diff rather than an assertion.
//! That property decays the moment
//! someone edits one by hand, drops a capture from a lab in beside them, or
//! regenerates from a template that still carries a real address — and
//! nothing about the resulting file looks wrong. The repository is public, so
//! the failure mode is publishing someone's traffic.
//!
//! So the invariant is asserted on the bytes, not on the intent:
//!
//! * no public-routable IPv4 address anywhere in the file;
//! * no run of 9 to 15 digits, the shape an E.164 number takes;
//! * every SIP URI host is either an IP literal or an `example.*` label
//!   reserved by RFC 2606 for documentation.
//!
//! The list is explicit rather than a directory walk. The other samples in
//! that directory come from published protocol-analysis sample sets and do
//! carry public addresses; sweeping the whole directory would either fail on
//! them or force the bar down to whatever they happen to satisfy. Adding a
//! generated fixture means adding it here.

use std::net::Ipv4Addr;
use std::path::PathBuf;

/// The fixtures `tests/gen-pcap-samples.py` and
/// `tests/gen-link-type-samples.py` write.
///
/// The three link-type fixtures are the second generator's; they carry the
/// link-layer framings — DLT_LOOP, and PPPoE inside Linux cooked capture v1
/// and v2 — that had decoder code and no capture behind it.
///
/// The last entry is the fuzz-corpus copy of `sip-register.pcap`; it is the
/// same bytes in a second place, and a regeneration that updates one and not
/// the other is exactly the drift this list exists to catch.
const GENERATED: &[&str] = &[
    "tests/pcap-samples/sip-register.pcap",
    "tests/pcap-samples/sip-proxy.pcap",
    "tests/pcap-samples/sip-sdp-example.pcap",
    "tests/pcap-samples/sip-auth-failure.pcapng",
    "tests/pcap-samples/sip-routing-error.pcapng",
    "tests/pcap-samples/sip-488-codec-reject.pcapng",
    "tests/pcap-samples/rtp-protocol.pcap",
    "tests/pcap-samples/sip-over-tcp.pcap",
    "tests/pcap-samples/b2bua-asterisk.pcapng",
    "tests/pcap-samples/sipp-branch-scenario.pcapng",
    "tests/pcap-samples/loopback-dlt-loop.pcap",
    "tests/pcap-samples/linux-sll-pppoe.pcap",
    "tests/pcap-samples/linux-sll2-pppoe.pcap",
    "fuzz/corpus/pcap_reader/sip-register.pcap",
];

/// Absolute path to a repository-relative file.
fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Whether `addr` is routable on the public internet.
///
/// Documentation ranges are excluded by name. `Ipv4Addr::is_documentation`
/// covers only 192.0.2.0/24 in stable Rust's definition of the term, while
/// RFC 5737 reserves three blocks and the generator uses all three.
fn is_public(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    let documentation = matches!(
        (o[0], o[1], o[2]),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    );
    !(documentation
        || addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_unspecified()
        // 240.0.0.0/4 reserved, and 100.64.0.0/10 carrier-grade NAT.
        || o[0] >= 240
        || (o[0] == 100 && (64..128).contains(&o[1])))
}

/// Every dotted quad in `data` that parses as an IPv4 address.
///
/// Deliberately scans the raw bytes rather than parsed SIP: a real address
/// can sit in a `User-Agent` version string, an SDP origin line, a Digest
/// realm or a comment, and every one of those reaches a reader.
fn ipv4_literals(data: &[u8]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if !data[i].is_ascii_digit() || (i > 0 && is_quad_char(data[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && is_quad_char(data[i]) {
            i += 1;
        }
        // A trailing digit-adjacent byte would make this a longer token.
        let text = std::str::from_utf8(&data[start..i]).unwrap_or_default();
        if let Ok(addr) = text.parse::<Ipv4Addr>() {
            out.push(addr);
        }
    }
    out
}

/// Bytes that can appear inside a dotted quad.
fn is_quad_char(byte: u8) -> bool {
    byte.is_ascii_digit() || byte == b'.'
}

/// Every maximal run of 9 to 15 ASCII digits in `data`.
///
/// The bound is the E.164 length range. A shorter run is an extension or a
/// port and a longer one is a session identifier, so neither reads as a
/// telephone number to someone scanning the file.
fn phone_shaped_runs(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if !data[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && data[i].is_ascii_digit() {
            i += 1;
        }
        let len = i - start;
        if (9..=15).contains(&len) {
            out.push(String::from_utf8_lossy(&data[start..i]).into_owned());
        }
    }
    out
}

/// Every host part of a `sip:`/`sips:` URI carrying a user part.
fn sip_uri_hosts(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for (idx, window) in data.windows(5).enumerate() {
        let mut cursor = match window {
            [b's', b'i', b'p', b':', _] => idx + 4,
            [b's', b'i', b'p', b's', b':'] => idx + 5,
            _ => continue,
        };
        // Walk to the '@', stopping at anything that ends a URI.
        let mut at = None;
        while let Some(&byte) = data.get(cursor) {
            if byte == b'@' {
                at = Some(cursor + 1);
                break;
            }
            if matches!(byte, b' ' | b'\r' | b'\n' | b'>' | b';' | b',' | b'"') {
                break;
            }
            cursor += 1;
        }
        let Some(host_start) = at else { continue };
        let mut end = host_start;
        while let Some(&byte) = data.get(end) {
            if matches!(byte, b' ' | b'\r' | b'\n' | b'>' | b';' | b',' | b'"') {
                break;
            }
            end += 1;
        }
        let host = String::from_utf8_lossy(&data[host_start..end]).into_owned();
        // Drop a trailing :port so `example.com:5060` classifies as its host.
        let host = match host.rsplit_once(':') {
            Some((left, right)) if right.chars().all(|c| c.is_ascii_digit()) => left.to_string(),
            _ => host,
        };
        if !host.is_empty() {
            out.push(host);
        }
    }
    out
}

/// A SIP URI host is documentation-safe when it is an IP literal or RFC 2606.
fn host_is_synthetic(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    host == "example.com"
        || host == "example.net"
        || host == "example.org"
        || host.ends_with(".example.com")
        || host.ends_with(".example.net")
        || host.ends_with(".example.org")
}

/// Not one public-routable IPv4 address survives in a generated fixture.
///
/// Asserted on every byte rather than on the addresses sipnab parses out,
/// because the address that leaks is the one nobody thought was an address.
#[test]
fn generated_fixtures_carry_no_public_routable_address() {
    for rel in GENERATED {
        let path = repo_path(rel);
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut public: Vec<Ipv4Addr> = ipv4_literals(&data)
            .into_iter()
            .filter(|a| is_public(*a))
            .collect();
        public.sort();
        public.dedup();
        assert!(
            public.is_empty(),
            "{rel} carries {} public-routable address(es); a generated fixture \
             must use RFC 5737 or RFC 1918 space only. First few: {:?}",
            public.len(),
            &public[..public.len().min(4)]
        );
    }
}

/// No digit run in a generated fixture can be read as a telephone number.
#[test]
fn generated_fixtures_carry_no_phone_shaped_digit_runs() {
    for rel in GENERATED {
        let path = repo_path(rel);
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut runs = phone_shaped_runs(&data);
        runs.sort();
        runs.dedup();
        assert!(
            runs.is_empty(),
            "{rel} carries {} run(s) of 9-15 digits, which read as E.164 \
             numbers. Shorten or lengthen them. First few: {:?}",
            runs.len(),
            &runs[..runs.len().min(4)]
        );
    }
}

/// Every SIP URI host is an IP literal or an RFC 2606 documentation label.
///
/// The one that motivated this: a load-generator fixture whose URIs pointed
/// at a domain that was neither reserved nor owned by the project. Nothing in
/// the capture looked wrong, and no test read the host at all.
#[test]
fn generated_fixtures_name_only_documentation_hosts() {
    for rel in GENERATED {
        let path = repo_path(rel);
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut offenders: Vec<String> = sip_uri_hosts(&data)
            .into_iter()
            .filter(|h| !host_is_synthetic(h))
            .collect();
        offenders.sort();
        offenders.dedup();
        assert!(
            offenders.is_empty(),
            "{rel} names {} SIP URI host(s) that are neither an IP literal \
             nor an example.* label: {:?}",
            offenders.len(),
            &offenders[..offenders.len().min(4)]
        );
    }
}

/// The fuzz seed and the sample it was copied from must stay identical.
///
/// They are the same capture in two places. Regenerating one and not the
/// other leaves two files with one name and different bytes, which is the
/// kind of drift that is only noticed when a fuzz reproducer stops
/// reproducing.
#[test]
fn the_fuzz_seed_matches_the_sample_it_copies() {
    let sample =
        std::fs::read(repo_path("tests/pcap-samples/sip-register.pcap")).expect("read the sample");
    let seed = std::fs::read(repo_path("fuzz/corpus/pcap_reader/sip-register.pcap"))
        .expect("read the fuzz seed");
    assert_eq!(
        sample, seed,
        "fuzz/corpus/pcap_reader/sip-register.pcap has drifted from \
         tests/pcap-samples/sip-register.pcap; regenerate both with \
         `python3 tests/gen-pcap-samples.py`"
    );
}
