// SPDX-License-Identifier: MIT OR Apache-2.0

//! One output file, one link type — or the export must refuse.
//!
//! A pcap file's global header carries a SINGLE link-layer type, and every
//! record in the file is decoded with it. Reading a set of captures whose
//! members were taken on different link layers (`-I a.pcap -I b.pcap`, a
//! directory, a glob, `--multi-device`) and writing them all to one `-O`
//! file therefore produces frames that any reader decodes with the wrong
//! link layer: an Ethernet frame read as Linux SLL, or the reverse. Nothing
//! about the result looks broken — the file opens, the frame count is right,
//! and the packets are simply not the packets that were captured.
//!
//! pcapng has the answer the format was designed for: one Interface
//! Description Block per interface, each declaring its own link type, and
//! every packet block naming the interface it came from. sipnab's writer
//! already emits IDBs, so mixed sets are written faithfully there.
//!
//! The oracle in this file reads the written bytes by hand — the pcap global
//! header's link-type field, and the pcapng IDB/EPB blocks — rather than
//! asking sipnab what it wrote. What matters is what a third party's reader
//! sees, and that is a property of the bytes.

use std::path::{Path, PathBuf};

/// A fresh temp directory for one test.
fn tmp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sipnab-mixed-link-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create temp dir");
    d
}

/// Path to a checked-in sample capture.
fn sample(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/pcap-samples")
        .join(name)
}

/// LINKTYPE_ETHERNET — `register-invite-reinvite-bye.pcap`.
const LINKTYPE_ETHERNET: u32 = 1;
/// LINKTYPE_LINUX_SLL — `speech_8k_ulaw.pcap`.
const LINKTYPE_LINUX_SLL: u32 = 113;
/// Packets in `speech_8k_ulaw.pcap` (Linux SLL, epoch-0 timestamps, so it
/// sorts first in capture order and its link type reaches the writer first).
const SLL_PACKETS: usize = 835;
/// Packets in `register-invite-reinvite-bye.pcap` (Ethernet).
const ETHERNET_PACKETS: usize = 229;

/// Run sipnab with the given args, returning `(stderr, exit_code)`.
fn run(args: &[&str]) -> (String, Option<i32>) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    (
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// The link type in a classic pcap file's 24-byte global header.
///
/// Hand-read from the bytes (magic decides the endianness) so the assertion
/// does not depend on any sipnab code — this is what libpcap, Wireshark and
/// `capinfos` read, and it is the only link type a classic pcap can state.
fn pcap_global_link_type(path: &Path) -> u32 {
    let bytes = std::fs::read(path).expect("read pcap");
    assert!(
        bytes.len() >= 24,
        "{} is too short to hold a pcap header",
        path.display()
    );
    let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
    let le = matches!(magic, 0xA1B2_C3D4 | 0xA1B2_3C4D);
    let raw: [u8; 4] = bytes[20..24].try_into().expect("4 bytes");
    if le {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    }
}

/// Every pcapng block in `path` as `(block_type, body)`, in file order.
///
/// A pcapng block is `type:u32, total_len:u32, body, total_len:u32`. Only
/// little-endian sections are handled, which is what sipnab writes on every
/// platform it supports.
fn pcapng_blocks(path: &Path) -> Vec<(u32, Vec<u8>)> {
    let bytes = std::fs::read(path).expect("read pcapng");
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 12 <= bytes.len() {
        let btype = u32::from_le_bytes(bytes[off..off + 4].try_into().expect("4 bytes"));
        let len = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().expect("4 bytes")) as usize;
        assert!(
            len >= 12 && off + len <= bytes.len(),
            "malformed pcapng block at offset {off}: len={len}"
        );
        out.push((btype, bytes[off + 8..off + len - 4].to_vec()));
        off += len;
    }
    out
}

/// The link type each Interface Description Block declares, in file order.
///
/// IDB body: `linktype:u16, reserved:u16, snaplen:u32, options…`.
fn pcapng_interface_link_types(path: &Path) -> Vec<u32> {
    pcapng_blocks(path)
        .into_iter()
        .filter(|(t, _)| *t == 0x0000_0001)
        .map(|(_, body)| u32::from(u16::from_le_bytes(body[0..2].try_into().expect("2 bytes"))))
        .collect()
}

/// The interface id each Enhanced Packet Block names, in file order.
///
/// EPB body: `interface_id:u32, ts_high:u32, ts_low:u32, caplen:u32, …`.
fn pcapng_epb_interface_ids(path: &Path) -> Vec<u32> {
    pcapng_blocks(path)
        .into_iter()
        .filter(|(t, _)| *t == 0x0000_0006)
        .map(|(_, body)| u32::from_le_bytes(body[0..4].try_into().expect("4 bytes")))
        .collect()
}

/// Writing an Ethernet capture and a Linux SLL capture into ONE classic pcap
/// cannot be done faithfully, so it must not be done at all.
///
/// Before this guard the run exited 0 with a file whose header said
/// "Ethernet" over frames that were not Ethernet: Wireshark decoded the SLL
/// frames as opaque `data`, every SIP message inside them vanished from the
/// dissection, and nothing in the file said so.
#[test]
fn plain_pcap_refuses_a_mixed_link_type_input_set() {
    let dir = tmp_dir("plain");
    let out = dir.join("out.pcap");
    let (stderr, code) = run(&[
        "-N",
        "-q",
        "--portrange",
        "1-65535",
        "-I",
        sample("speech_8k_ulaw.pcap").to_str().expect("utf-8 path"),
        "-I",
        sample("register-invite-reinvite-bye.pcap")
            .to_str()
            .expect("utf-8 path"),
        "-O",
        out.to_str().expect("utf-8 path"),
    ]);

    assert_ne!(
        code,
        Some(0),
        "a mixed-link-type export must not report success\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("link type") || stderr.contains("link-layer type"),
        "the refusal must say the link types differ\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("113") && stderr.contains('1'),
        "the refusal must name both link types so the operator can see which \
         captures disagree\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--pcapng"),
        "the refusal must name the format that CAN carry both\nstderr:\n{stderr}"
    );

    // Whatever was written before the refusal must still be honest: the file
    // declares the link type of the frames it actually holds.
    if out.exists() {
        assert_eq!(
            pcap_global_link_type(&out),
            LINKTYPE_LINUX_SLL,
            "the partial file must declare the link type of the frames in it"
        );
    }
}

/// The same input set written as pcapng is faithful: one interface per link
/// type, each declaring its own, and every packet block naming the interface
/// it came from. Nothing is dropped and nothing is mislabelled.
#[test]
fn pcapng_gives_each_link_type_its_own_interface() {
    let dir = tmp_dir("pcapng");
    let out = dir.join("out.pcapng");
    let (stderr, code) = run(&[
        "-N",
        "-q",
        "--pcapng",
        "--portrange",
        "1-65535",
        "-I",
        sample("speech_8k_ulaw.pcap").to_str().expect("utf-8 path"),
        "-I",
        sample("register-invite-reinvite-bye.pcap")
            .to_str()
            .expect("utf-8 path"),
        "-O",
        out.to_str().expect("utf-8 path"),
    ]);

    assert_eq!(
        code,
        Some(0),
        "pcapng can represent a mixed set; it must not refuse\nstderr:\n{stderr}"
    );

    assert_eq!(
        pcapng_interface_link_types(&out),
        vec![LINKTYPE_LINUX_SLL, LINKTYPE_ETHERNET],
        "one IDB per link type, in first-appearance order (SLL sorts first: \
         its timestamps are epoch-0)"
    );

    let ids = pcapng_epb_interface_ids(&out);
    assert_eq!(
        ids.len(),
        SLL_PACKETS + ETHERNET_PACKETS,
        "every packet from both captures is written"
    );
    assert_eq!(
        ids.iter().filter(|&&id| id == 0).count(),
        SLL_PACKETS,
        "every SLL frame names the SLL interface"
    );
    assert_eq!(
        ids.iter().filter(|&&id| id == 1).count(),
        ETHERNET_PACKETS,
        "every Ethernet frame names the Ethernet interface — not interface 0, \
         whose IDB declares SLL"
    );
}

/// A single-link-type set is untouched by the guard: one interface, one IDB,
/// every packet on it. The fix must not fragment ordinary captures.
#[test]
fn uniform_link_type_still_writes_one_interface() {
    let dir = tmp_dir("uniform");
    let out = dir.join("out.pcapng");
    let (stderr, code) = run(&[
        "-N",
        "-q",
        "--pcapng",
        "--portrange",
        "1-65535",
        "-I",
        sample("register-invite-reinvite-bye.pcap")
            .to_str()
            .expect("utf-8 path"),
        "-O",
        out.to_str().expect("utf-8 path"),
    ]);

    assert_eq!(
        code,
        Some(0),
        "uniform export must succeed\nstderr:\n{stderr}"
    );
    assert_eq!(
        pcapng_interface_link_types(&out),
        vec![LINKTYPE_ETHERNET],
        "a single-link-type capture keeps exactly one interface"
    );
    assert!(
        pcapng_epb_interface_ids(&out).iter().all(|&id| id == 0),
        "every packet stays on interface 0"
    );
}

/// And plain pcap is untouched too: a uniform set still writes a classic
/// pcap declaring that link type, exit 0.
#[test]
fn uniform_link_type_still_writes_plain_pcap() {
    let dir = tmp_dir("uniform-plain");
    let out = dir.join("out.pcap");
    let (stderr, code) = run(&[
        "-N",
        "-q",
        "--portrange",
        "1-65535",
        "-I",
        sample("speech_8k_ulaw.pcap").to_str().expect("utf-8 path"),
        "-O",
        out.to_str().expect("utf-8 path"),
    ]);

    assert_eq!(
        code,
        Some(0),
        "uniform export must succeed\nstderr:\n{stderr}"
    );
    assert_eq!(
        pcap_global_link_type(&out),
        LINKTYPE_LINUX_SLL,
        "a classic pcap of an SLL capture declares SLL"
    );
}
