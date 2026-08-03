// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every exported frame must name the capture file it actually came from.
//!
//! An exported pcapng is evidence. Its Interface Description Blocks say where
//! the frames came from, and every Enhanced Packet Block points at one of
//! them. Reading a set of captures (`-I a.pcap -I b.pcap`, a directory, a
//! glob) and writing them to one `--pcapng` file used to record a SINGLE IDB,
//! named after the FIRST input, with every frame referencing it — so the
//! frames read out of the second file claimed, in the file's own metadata, to
//! have been captured from the first. Nothing looks wrong: the file opens, the
//! frame count is right, and a reader has no reason to doubt the source.
//!
//! That is worse than recording no source at all. A frame with no attribution
//! invites the question; a frame with a confident wrong one does not.
//!
//! The oracle here reads the written bytes by hand — pcapng block headers, the
//! IDB `if_name` option, the EPB `interface_id` field — rather than asking
//! sipnab what it wrote. What matters is what a third party's reader sees, and
//! that is a property of the bytes. The same numbers are reproducible outside
//! the test suite with `capinfos -I` and
//! `tshark -T fields -e frame.interface_name`.

use std::path::{Path, PathBuf};

/// A fresh temp directory for one test.
fn tmp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sipnab-provenance-{name}"));
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

/// A checked-in sample path as the `-I` argument string.
fn sample_arg(name: &str) -> String {
    sample(name).to_str().expect("utf-8 path").to_string()
}

/// `sip-rtp-g711.pcap`: Ethernet, first packet 2016-11-26, so the input-set
/// resolver (which orders chronologically) reads it FIRST whichever order the
/// `-I` arguments are given in. Packet count per `capinfos -c`.
const G711_FILE: &str = "sip-rtp-g711.pcap";
/// Packets in [`G711_FILE`].
const G711_PACKETS: usize = 852;

/// `register-invite-reinvite-bye.pcap`: Ethernet, first packet 2026-07-08, so
/// it is read SECOND. Packet count per `capinfos -c`.
const REGISTER_FILE: &str = "register-invite-reinvite-bye.pcap";
/// Packets in [`REGISTER_FILE`].
const REGISTER_PACKETS: usize = 229;

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

/// The `if_name` option (code 2) of an Interface Description Block body, or
/// `None` when the IDB records no name.
///
/// IDB body: `linktype:u16, reserved:u16, snaplen:u32, options…`, and an
/// option is `code:u16, len:u16, value, padding to a 4-byte boundary`.
fn idb_if_name(body: &[u8]) -> Option<String> {
    /// `opt_endofopt`.
    const OPT_END: u16 = 0;
    /// `if_name`.
    const OPT_IF_NAME: u16 = 2;

    let mut off = 8usize;
    while off + 4 <= body.len() {
        let code = u16::from_le_bytes(body[off..off + 2].try_into().expect("2 bytes"));
        let len = u16::from_le_bytes(body[off + 2..off + 4].try_into().expect("2 bytes")) as usize;
        if code == OPT_END {
            break;
        }
        let start = off + 4;
        let end = start + len;
        if end > body.len() {
            break;
        }
        if code == OPT_IF_NAME {
            return Some(String::from_utf8_lossy(&body[start..end]).into_owned());
        }
        off = end + (4 - end % 4) % 4;
    }
    None
}

/// The `if_name` each Interface Description Block declares, in file order —
/// index into this list IS the `interface_id` an EPB references.
fn pcapng_interface_names(path: &Path) -> Vec<Option<String>> {
    pcapng_blocks(path)
        .into_iter()
        .filter(|(t, _)| *t == 0x0000_0001)
        .map(|(_, body)| idb_if_name(&body))
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

/// How many frames reference each interface id, as a vector indexed by id.
fn frames_per_interface(path: &Path, interfaces: usize) -> Vec<usize> {
    let mut counts = vec![0usize; interfaces];
    for id in pcapng_epb_interface_ids(path) {
        let id = id as usize;
        assert!(
            id < interfaces,
            "EPB references interface {id}, but the file declares only {interfaces}"
        );
        counts[id] += 1;
    }
    counts
}

/// Two input files at the SAME link type must each get their own interface,
/// and every frame must reference the one it was actually read from.
///
/// This is the defect in its pure form: the link-type fix separates inputs
/// captured on DIFFERENT link layers, but two ordinary Ethernet captures
/// collapsed onto one IDB named after the first input. Here that would leave
/// 852 of 1081 frames — 79% of the export — naming a file they never came
/// from.
///
/// The per-interface frame counts are the positive control: collapsing both
/// sources onto one interface fails the interface count, and splitting frames
/// any other way fails the counts, which are each source file's own
/// `capinfos -c` total.
#[test]
fn pcapng_two_same_link_type_inputs_get_one_interface_each() {
    let dir = tmp_dir("two-files");
    let out = dir.join("out.pcapng");
    // REGISTER_FILE is given FIRST on the command line but read SECOND (the
    // set resolves chronologically), which is exactly the shape that made the
    // bug misattribute the majority of the export: the writer was told the
    // first `-I` argument and every frame was stamped with it.
    let (stderr, code) = run(&[
        "-N",
        "-q",
        "--pcapng",
        "--portrange",
        "1-65535",
        "-I",
        &sample_arg(REGISTER_FILE),
        "-I",
        &sample_arg(G711_FILE),
        "-O",
        out.to_str().expect("utf-8 path"),
    ]);

    assert_eq!(code, Some(0), "export must succeed\nstderr:\n{stderr}");

    let names = pcapng_interface_names(&out);
    assert_eq!(
        names,
        vec![Some(sample_arg(G711_FILE)), Some(sample_arg(REGISTER_FILE))],
        "one IDB per source file, each naming that file, in read order \
         (G711 sorts first: its packets are from 2016)"
    );

    assert_eq!(
        frames_per_interface(&out, names.len()),
        vec![G711_PACKETS, REGISTER_PACKETS],
        "every frame references the interface of the file it was read from — \
         the counts are each source file's own packet total"
    );
}

/// One input file must still produce exactly one interface, named after it,
/// with every frame on it. Per-source provenance must not fragment ordinary
/// single-capture exports.
#[test]
fn pcapng_single_input_still_writes_exactly_one_interface() {
    let dir = tmp_dir("one-file");
    let out = dir.join("out.pcapng");
    let (stderr, code) = run(&[
        "-N",
        "-q",
        "--pcapng",
        "--portrange",
        "1-65535",
        "-I",
        &sample_arg(REGISTER_FILE),
        "-O",
        out.to_str().expect("utf-8 path"),
    ]);

    assert_eq!(code, Some(0), "export must succeed\nstderr:\n{stderr}");
    assert_eq!(
        pcapng_interface_names(&out),
        vec![Some(sample_arg(REGISTER_FILE))],
        "a single input keeps exactly one interface, named after it"
    );
    assert_eq!(
        frames_per_interface(&out, 1),
        vec![REGISTER_PACKETS],
        "every frame of the single input stays on interface 0"
    );
}

/// A directory input names the FILES it expanded to, not the directory.
///
/// `-I /captures` is the ring-buffer shape sipnab is pointed at in the field.
/// The writer is handed the `-I` argument as its capture source, which is the
/// directory — a thing no frame was ever captured from. It must not appear as
/// an interface, and each expanded file must appear as its own.
#[test]
fn pcapng_directory_input_names_the_files_not_the_directory() {
    let dir = tmp_dir("dir-input");
    let inputs = dir.join("captures");
    std::fs::create_dir_all(&inputs).expect("create input dir");
    for name in [G711_FILE, REGISTER_FILE] {
        std::fs::copy(sample(name), inputs.join(name)).expect("stage input");
    }
    let out = dir.join("out.pcapng");
    let (stderr, code) = run(&[
        "-N",
        "-q",
        "--pcapng",
        "--portrange",
        "1-65535",
        "-I",
        inputs.to_str().expect("utf-8 path"),
        "-O",
        out.to_str().expect("utf-8 path"),
    ]);

    assert_eq!(code, Some(0), "export must succeed\nstderr:\n{stderr}");

    let names = pcapng_interface_names(&out);
    let dir_arg = inputs.to_str().expect("utf-8 path").to_string();
    assert!(
        !names.contains(&Some(dir_arg.clone())),
        "the directory itself is not a capture source: {names:?}"
    );
    assert_eq!(
        names,
        vec![
            Some(inputs.join(G711_FILE).display().to_string()),
            Some(inputs.join(REGISTER_FILE).display().to_string()),
        ],
        "one IDB per expanded file, each naming that file"
    );
    assert_eq!(
        frames_per_interface(&out, names.len()),
        vec![G711_PACKETS, REGISTER_PACKETS],
        "each expanded file's frames reference its own interface"
    );
}
