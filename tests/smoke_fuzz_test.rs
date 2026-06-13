//! Smoke-fuzz: every parser reachable from raw, attacker-controlled
//! packet bytes must return a Result/Option, never panic.
//!
//! cargo-fuzz needs a nightly toolchain that isn't available here, so
//! this is an in-process volume fuzzer on the stable toolchain: each
//! parse entry point (the same set the fuzz/ targets cover, plus the
//! full link-layer decap chain and the pcap file reader) is fed a large
//! number of random and structurally-mutated inputs under
//! `catch_unwind`. A panic in any of them is a remote DoS on a capture
//! process, so a caught panic fails the test with the offending input
//! hex-dumped for a repro seed.
//!
//! This is not a replacement for coverage-guided fuzzing — it is the
//! always-on regression floor that runs in `cargo test`.

use std::panic::{AssertUnwindSafe, catch_unwind};

/// Tiny deterministic xorshift PRNG — no rand dependency, reproducible
/// across runs so a failure is always replayable from the seed.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// A random buffer up to `max` bytes (including empty).
fn random_bytes(rng: &mut Rng, max: usize) -> Vec<u8> {
    let n = rng.below(max + 1);
    (0..n).map(|_| rng.byte()).collect()
}

/// Mutate a seed: truncate, extend, single/multi bit-flips, byte
/// splices. Exercises the "valid-ish but corrupt" region that pure
/// random rarely reaches (length fields, offsets, counts).
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    let ops = 1 + rng.below(6);
    for _ in 0..ops {
        if v.is_empty() {
            v.push(rng.byte());
            continue;
        }
        match rng.below(6) {
            0 => {
                // bit flip
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 => {
                // overwrite a byte (often hits length/count fields)
                let i = rng.below(v.len());
                v[i] = rng.byte();
            }
            2 => {
                // truncate
                let keep = rng.below(v.len());
                v.truncate(keep);
            }
            3 => {
                // extend
                for _ in 0..rng.below(8) {
                    v.push(rng.byte());
                }
            }
            4 => {
                // set a 2-byte big-endian field to a large value
                if v.len() >= 2 {
                    let i = rng.below(v.len() - 1);
                    v[i] = 0xff;
                    v[i + 1] = 0xff;
                }
            }
            _ => {
                // duplicate-grow (memory-amplification probe)
                let take = rng.below(v.len()) + 1;
                let chunk: Vec<u8> = v[..take].to_vec();
                v.extend_from_slice(&chunk);
            }
        }
        // hard cap so a grow op can't OOM the test itself
        if v.len() > 70_000 {
            v.truncate(70_000);
        }
    }
    v
}

/// Run `f` over `iters` random + mutated inputs; panic = test failure
/// with the input hex-dumped.
fn pound<F: Fn(&[u8])>(name: &str, seeds: &[&[u8]], iters: usize, f: F) {
    let mut rng = Rng::new(0x5113_5ab0_d00d_1234u64 ^ name.bytes().map(|b| b as u64).sum::<u64>());
    for i in 0..iters {
        let input = if !seeds.is_empty() && rng.below(2) == 0 {
            let seed = seeds[rng.below(seeds.len())];
            mutate(&mut rng, seed)
        } else {
            random_bytes(&mut rng, 2048)
        };
        let r = catch_unwind(AssertUnwindSafe(|| f(&input)));
        if r.is_err() {
            panic!(
                "PARSER PANIC in `{name}` on iteration {i}\n\
                 input ({} bytes): {}\n\
                 (a parser reachable from packet bytes must never panic)",
                input.len(),
                hex(&input),
            );
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<String>()
}

// ---- realistic seeds so mutation starts near valid structure -------

fn sip_seed() -> Vec<u8> {
    b"INVITE sip:bob@example.com SIP/2.0\r\n\
      Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n\
      From: <sip:alice@example.com>;tag=1\r\n\
      To: <sip:bob@example.com>\r\n\
      Call-ID: abc@10.0.0.1\r\n\
      CSeq: 1 INVITE\r\n\
      Content-Type: application/sdp\r\n\
      Content-Length: 0\r\n\r\n"
        .to_vec()
}

fn sdp_seed() -> Vec<u8> {
    b"v=0\r\no=alice 1 1 IN IP4 10.0.0.1\r\ns=call\r\n\
      c=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0 8\r\n\
      a=rtpmap:0 PCMU/8000\r\n"
        .to_vec()
}

fn rtp_seed() -> Vec<u8> {
    // V=2, PT=0, has CSRC + extension bits exercised by mutation
    vec![
        0x80, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03,
        0x04,
    ]
}

fn rtcp_seed() -> Vec<u8> {
    // SR header: V=2, PT=200, length field present for mutation
    vec![
        0x80, 0xc8, 0x00, 0x06, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ]
}

fn eth_ipv4_udp_sip() -> Vec<u8> {
    // Ethernet + IPv4 + UDP + a SIP body, so decap mutation walks the
    // whole link->ip->udp->payload chain.
    let mut p = vec![
        // eth: dst, src, ethertype=0x0800
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
    ];
    // IPv4 header (20 bytes): ihl=5 v=4, ... proto=17 (UDP)
    let ip: [u8; 20] = [
        0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2,
    ];
    p.extend_from_slice(&ip);
    // UDP header (8 bytes): sport 5060, dport 5060, len, csum
    p.extend_from_slice(&[0x13, 0xc4, 0x13, 0xc4, 0x00, 0x10, 0x00, 0x00]);
    p.extend_from_slice(b"INVITE sip:b@x SIP/2.0\r\n\r\n");
    p
}

// ---- the parser surface --------------------------------------------

const ITERS: usize = 40_000;

#[test]
fn fuzz_sip_parser_no_panic() {
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};
    let seed = sip_seed();
    let seeds: &[&[u8]] = &[&seed];
    pound("sip_parser", seeds, ITERS, |d| {
        let _ = sipnab::sip::parser::parse_sip(
            d,
            Utc::now(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            5060,
            5060,
            sipnab::capture::parse::TransportProto::Udp,
        );
    });
}

#[test]
fn fuzz_sdp_parser_no_panic() {
    let seed = sdp_seed();
    let seeds: &[&[u8]] = &[&seed];
    pound("sdp_parser", seeds, ITERS, |d| {
        let _ = sipnab::sip::sdp::parse_sdp(d);
    });
}

#[test]
fn fuzz_rtp_parser_no_panic() {
    let seed = rtp_seed();
    let seeds: &[&[u8]] = &[&seed];
    pound("rtp_parser", seeds, ITERS, |d| {
        let _ = sipnab::rtp::parser::parse_rtp_header(d);
    });
}

#[test]
fn fuzz_rtcp_parser_no_panic() {
    let seed = rtcp_seed();
    let seeds: &[&[u8]] = &[&seed];
    pound("rtcp_parser", seeds, ITERS, |d| {
        let _ = sipnab::rtp::rtcp::parse_rtcp(d);
    });
}

#[cfg(feature = "hep")]
#[test]
fn fuzz_hep_parser_no_panic() {
    pound("hep_parser", &[], ITERS, |d| {
        let _ = sipnab::capture::hep::parse_hep(d);
    });
}

#[test]
fn fuzz_websocket_frame_no_panic() {
    pound("websocket_frame", &[], ITERS, |d| {
        let _ = sipnab::capture::websocket::unwrap_websocket_frame(d);
    });
}

#[test]
fn fuzz_full_decap_chain_no_panic() {
    // The real attacker surface: raw link-layer bytes through
    // parse_packet (eth/IP/UDP/TCP/encap decap). Hit a few common
    // link types so the link-layer dispatch is exercised.
    use chrono::Utc;
    use sipnab::capture::packet::Packet;
    let seed = eth_ipv4_udp_sip();
    let seeds: &[&[u8]] = &[&seed];
    for &lt in &[
        1i32, /*EN10MB*/
        101,  /*RAW*/
        113,  /*LINUX_SLL*/
        12,   /*RAW alt*/
        276,
    ] {
        pound(&format!("decap_lt{lt}"), seeds, ITERS / 2, |d| {
            let pkt = Packet::new(Utc::now(), d.to_vec(), d.len(), d.len(), None, lt);
            let _ = sipnab::capture::parse::parse_packet(&pkt);
        });
    }
}

#[test]
fn fuzz_text_entry_points_no_panic() {
    // The remaining fuzz/ entry points take &str or a small struct.
    // Covering them here keeps the always-on floor complete AND
    // compile-checks their signatures so the fuzz suite cannot silently
    // bit-rot (the sip_parser target had drifted to a stale `&str`
    // transport arg that no longer compiled).
    let dsl_seed = b"method == INVITE and from contains alice".to_vec();
    let dsl_seeds: &[&[u8]] = &[&dsl_seed];
    pound("filter_dsl", dsl_seeds, ITERS, |d| {
        if let Ok(s) = std::str::from_utf8(d) {
            let _ = sipnab::sip::dsl::FilterExpr::parse(s);
        }
    });
}

#[cfg(feature = "tls")]
#[test]
fn fuzz_tls_text_entry_points_no_panic() {
    let id_seed =
        b"eyJhbGciOiJFUzI1NiJ9.eyJhdHRlc3QiOiJBIn0.sig;info=<https://x/c.cer>;alg=ES256;ppt=shaken"
            .to_vec();
    let id_seeds: &[&[u8]] = &[&id_seed];
    pound("stir_shaken", id_seeds, ITERS, |d| {
        if let Ok(s) = std::str::from_utf8(d) {
            let _ = sipnab::sip::stir_shaken::parse_identity_header(s);
        }
    });

    pound("tls_records", &[], ITERS, |d| {
        let _ = sipnab::capture::tls::parse_tls_records(d);
    });

    let kl_seed = b"CLIENT_RANDOM 00112233445566778899aabbccddeeff 0011223344".to_vec();
    let kl_seeds: &[&[u8]] = &[&kl_seed];
    pound("keylog_line", kl_seeds, ITERS, |d| {
        if let Ok(s) = std::str::from_utf8(d) {
            let _ = sipnab::capture::tls::parse_keylog_line(s);
        }
    });

    let crypto_seed =
        b"AES_CM_128_HMAC_SHA1_80\ninline:WVNfX19zZW1jdGwgKytom9vYzj1zdGV2aW4=|2^20|1:32".to_vec();
    let crypto_seeds: &[&[u8]] = &[&crypto_seed];
    pound("srtp_keys", crypto_seeds, ITERS, |d| {
        if let Ok(s) = std::str::from_utf8(d) {
            let (suite, key_params) = match s.find('\n') {
                Some(pos) => (&s[..pos], &s[pos + 1..]),
                None => ("AES_CM_128_HMAC_SHA1_80", s),
            };
            let crypto = sipnab::sip::sdp::SdpCrypto {
                tag: 1,
                suite: suite.to_string(),
                key_params: key_params.to_string(),
            };
            let _ = sipnab::rtp::srtp::extract_srtp_keys(&crypto);
        }
    });
}

#[test]
fn fuzz_pcap_reader_no_panic() {
    // Malformed pcap/pcapng FILE input — same trust level as a packet
    // when the file comes from an untrusted source.
    let mut pcap_seed = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0,
        0x01, 0, 0, 0,
    ];
    pcap_seed.extend_from_slice(&[0u8; 64]);
    let pcapng_seed = vec![
        0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0, 0, 0, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1c, 0, 0, 0,
    ];
    let seeds: &[&[u8]] = &[&pcap_seed, &pcapng_seed];
    pound("pcap_reader", seeds, ITERS, |d| {
        if let Ok(r) = sipnab::capture::pcap_reader::PcapReader::new(d) {
            // drain it — iterate all packets the malformed file claims
            for (guard, _pkt) in r.enumerate() {
                if guard > 100_000 {
                    break;
                }
            }
        }
    });
}
