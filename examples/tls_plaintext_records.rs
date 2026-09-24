// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS without keys, the half that needs no kernel: what sipnab makes of the
//! records its BPF program hands it.
//!
//! `--uprobe-tls --uprobe-backend bpf` has two halves. The live half installs
//! a uprobe on the TLS library's write function and a probe on `tcp_sendmsg`,
//! pairs the two, and publishes one record per write into a perf ring. That
//! needs root, a sipnab built with `--features bpf` and a kernel carrying BTF,
//! so no CI runner can run it. The other half turns each record into a packet
//! the dialog store understands, and that half is where a wrong answer would
//! be invented: an address the program never observed, or bytes that are not
//! the application's message.
//!
//! This example runs the second half on its own. It lays each record out with
//! [`TlsRecord`], the type the kernel program writes through, so the bytes are
//! the bytes the ring carries, and passes them through
//! [`bpf_record::decode`](sipnab::capture::uprobe::bpf_record::decode), the
//! function the BPF backend calls on every sample. Then it builds dialogs the
//! way `call_summary` does.
//!
//! The four records are one client and server in a single `python3` process,
//! pid 349147, the shape of the measured run in cookbook recipe 7h:
//!
//! 1. a REGISTER from 127.0.0.1:36160 to 127.0.0.1:15061, paired with its socket;
//! 2. the 200 OK back on the same connection;
//! 3. an OPTIONS the TLS library buffered rather than sent, so the program
//!    paired it with no `tcp_sendmsg` and set no `FLAG_HAS_TUPLE`. sipnab
//!    reports it with no peer rather than guessing one;
//! 4. a write that is not SIP, which sipnab drops.
//!
//! Run it:
//!
//! ```sh
//! cargo run --example tls_plaintext_records
//! ```
//!
//! `scripts/smoke-clients.sh` runs it in CI and checks every line it prints.

#[cfg(target_os = "linux")]
fn main() {
    use sipnab::DialogStore;
    use sipnab::capture::parse::parse_packet;
    use sipnab::capture::uprobe::bpf_record::decode;
    use sipnab::sip::parser::parse_sip;
    use sipnab_bpf_types::{FAMILY_IPV4, FLAG_HAS_TUPLE, TlsRecord};

    const PID: u32 = 349_147;

    /// One perf sample: the record header, then the bytes the application
    /// wrote. `tuple` is the connection the program paired the write with.
    fn sample(tuple: Option<(u16, u16)>, payload: &[u8]) -> Vec<u8> {
        let mut rec = TlsRecord {
            pid: PID,
            tid: PID,
            len: u32::try_from(payload.len()).expect("a short message"),
            ..TlsRecord::ZEROED
        };
        rec.comm[..7].copy_from_slice(b"python3");
        if let Some((sport, dport)) = tuple {
            rec.flags = FLAG_HAS_TUPLE;
            rec.family = FAMILY_IPV4;
            rec.saddr[..4].copy_from_slice(&[127, 0, 0, 1]);
            rec.daddr[..4].copy_from_slice(&[127, 0, 0, 1]);
            rec.sport = sport;
            rec.dport = dport;
        }
        let mut bytes = rec.header_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    let register = "REGISTER sip:127.0.0.1:15061 SIP/2.0\r\n\
        Via: SIP/2.0/TLS 127.0.0.1:36160;branch=z9hG4bK-tls-1\r\n\
        From: <sip:alice@127.0.0.1>;tag=a1\r\n\
        To: <sip:alice@127.0.0.1>\r\n\
        Call-ID: tls-reg-1@127.0.0.1\r\n\
        CSeq: 1 REGISTER\r\n\
        Contact: <sip:alice@127.0.0.1:36160;transport=tls>\r\n\
        Content-Length: 0\r\n\r\n";
    let ok = "SIP/2.0 200 OK\r\n\
        Via: SIP/2.0/TLS 127.0.0.1:36160;branch=z9hG4bK-tls-1\r\n\
        From: <sip:alice@127.0.0.1>;tag=a1\r\n\
        To: <sip:alice@127.0.0.1>;tag=r1\r\n\
        Call-ID: tls-reg-1@127.0.0.1\r\n\
        CSeq: 1 REGISTER\r\n\
        Content-Length: 0\r\n\r\n";
    let options = "OPTIONS sip:127.0.0.1:15061 SIP/2.0\r\n\
        Via: SIP/2.0/TLS 127.0.0.1:36172;branch=z9hG4bK-tls-2\r\n\
        From: <sip:alice@127.0.0.1>;tag=a2\r\n\
        To: <sip:127.0.0.1:15061>\r\n\
        Call-ID: tls-opt-1@127.0.0.1\r\n\
        CSeq: 1 OPTIONS\r\n\
        Content-Length: 0\r\n\r\n";
    let records = [
        sample(Some((36160, 15061)), register.as_bytes()),
        sample(Some((15061, 36160)), ok.as_bytes()),
        sample(None, options.as_bytes()),
        sample(Some((36160, 15061)), b"GET /health HTTP/1.1\r\n\r\n"),
    ];

    let mut dialogs = DialogStore::new(64, false);
    let mut sip_messages = 0_usize;
    // Numbered as the backend numbers them: only a record that became a
    // packet takes an ordinal.
    let mut ordinal = 0_u64;
    for (n, raw) in records.iter().enumerate() {
        let Some(packet) = decode(raw, ordinal) else {
            println!("record {n} dropped: not a SIP message");
            continue;
        };
        let source = format!("{}#{ordinal}", packet.interface.as_deref().unwrap_or("?"));
        ordinal += 1;
        let parsed = parse_packet(&packet).expect("a decoded record carries its own addresses");
        let msg = parse_sip(
            &parsed.payload,
            parsed.timestamp,
            parsed.src_addr,
            parsed.dst_addr,
            parsed.src_port,
            parsed.dst_port,
            parsed.transport,
        )
        .expect("decode passed only SIP");
        let first = String::from_utf8_lossy(&parsed.payload);
        let first = first.lines().next().unwrap_or_default();
        let label = if first.starts_with("SIP/2.0 ") {
            first.trim_start_matches("SIP/2.0 ")
        } else {
            first.split(' ').next().unwrap_or_default()
        };
        println!(
            "{label:<10} {}:{} -> {}:{}  TCP  {source}",
            parsed.src_addr, parsed.src_port, parsed.dst_addr, parsed.dst_port
        );
        sip_messages += 1;
        dialogs.process_message(msg);
    }

    println!(
        "{} records, {sip_messages} SIP messages, {} dialogs",
        records.len(),
        dialogs.len()
    );
    for d in dialogs.iter() {
        let status = d
            .final_status_code()
            .map(|code| format!(" [{code}]"))
            .unwrap_or_default();
        println!(
            "{:<9} {:?}{status}  {} -> {}  ({} messages)  {}",
            d.method.as_str(),
            d.state(),
            d.from_user.as_deref().unwrap_or("?"),
            d.to_user.as_deref().unwrap_or("?"),
            d.messages.len(),
            d.call_id,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("The uprobe capture source, and so this example, is Linux-only.");
}
