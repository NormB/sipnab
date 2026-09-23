// SPDX-License-Identifier: MIT OR Apache-2.0

//! The archive and password layer never panics or hangs on hostile bytes.
//!
//! `fuzz/fuzz_targets/archive_password.rs` feeds libFuzzer's inputs to
//! [`sipnab::capture::archive::fuzz_one_archive`]. This replays that same
//! entry point over adversarial seeds and a deterministic mutation sweep of
//! real archives, built here, so the contract holds in every `cargo test`
//! and not only in the weekly fuzz run. No archive bytes are committed.
#![cfg(feature = "archive")]

use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use sipnab::capture::archive::fuzz_one_archive;

/// A password nobody wrote down.
fn mint() -> Vec<u8> {
    format!("fz{:x}", std::process::id() as u64 * 2_654_435_761).into_bytes()
}

/// One fuzz input: a length byte, the password, then the archive.
fn input(password: &[u8], archive: &[u8]) -> Vec<u8> {
    let mut v = vec![password.len() as u8];
    v.extend_from_slice(password);
    v.extend_from_slice(archive);
    v
}

fn zip_of(password: Option<&[u8]>) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let base = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let opts = match password {
        Some(pw) => base.with_aes_encryption_bytes(zip::AesMode::Aes256, pw),
        None => base,
    };
    w.start_file("a.pcap", opts).expect("start");
    let mut pcap = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    pcap.extend_from_slice(&[0u8; 16]);
    pcap.extend_from_slice(&[1u8; 200]);
    w.write_all(&pcap).expect("write");
    w.finish().expect("finish").into_inner()
}

fn sevenz_of(password: &str) -> Vec<u8> {
    use sevenz_rust2::encoder_options::AesEncoderOptions;
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderMethod, Password};
    let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).expect("writer");
    w.set_content_methods(vec![
        AesEncoderOptions::new(Password::from(password)).into(),
        EncoderMethod::LZMA2.into(),
    ]);
    let data = [7u8; 300];
    w.push_archive_entry(ArchiveEntry::new_file("a.pcap"), Some(&data[..]))
        .expect("entry");
    w.finish().expect("finish").into_inner()
}

/// Run one input, and say whether it panicked or took too long.
fn survives(data: &[u8]) -> Result<(), String> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let started = Instant::now();
    let res = catch_unwind(AssertUnwindSafe(|| fuzz_one_archive(data)));
    std::panic::set_hook(prev);
    if res.is_err() {
        return Err(format!("panicked on {} byte(s)", data.len()));
    }
    if started.elapsed() > Duration::from_secs(20) {
        return Err(format!(
            "took {:?} on {} byte(s)",
            started.elapsed(),
            data.len()
        ));
    }
    Ok(())
}

#[test]
fn hostile_archives_never_panic_or_hang() {
    let pw = mint();
    let pw_text = String::from_utf8(pw.clone()).expect("ascii");
    let zip_aes = zip_of(Some(&pw));
    let zip_plain = zip_of(None);
    let sz = sevenz_of(&pw_text);
    let mut seeds: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        input(&pw, b"PK\x03\x04"),
        input(&pw, b"PK\x05\x06\0\0\0\0\xff\xff\xff\xff"),
        input(&pw, &[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 4]),
        input(&pw, &zip_aes),
        input(b"", &zip_aes),
        input(&pw, &zip_plain),
        input(&pw, &sz),
        input(b"x", &sz),
    ];
    // Every truncation of each real archive, at a stride.
    for archive in [&zip_aes, &zip_plain, &sz] {
        for cut in (0..archive.len()).step_by(7) {
            seeds.push(input(&pw, &archive[..cut]));
        }
    }
    // A deterministic flip sweep over each.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for archive in [&zip_aes, &sz] {
        for _ in 0..150 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let mut m = archive.clone();
            let at = (state >> 33) as usize % m.len();
            m[at] ^= (state >> 8) as u8 | 1;
            seeds.push(input(&pw, &m));
        }
    }
    let failures: Vec<String> = seeds.iter().filter_map(|s| survives(s).err()).collect();
    assert!(failures.is_empty(), "{failures:?}");
}
