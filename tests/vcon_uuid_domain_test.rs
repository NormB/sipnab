// SPDX-License-Identifier: MIT OR Apache-2.0

//! `[vcon] uuid_domain`, on the shipped binary: a container's uuid follows
//! the layout of draft-ietf-vcon-vcon-core-04 section 4.1.2, a value that is
//! not a fully qualified host name is refused at startup naming the key, and
//! a run without the key writes the uuid it wrote before.
//!
//! [Section 4.1.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.2):
//! "The value of the string SHOULD be generated using the version 8 UUID
//! defined in [UUID] which is generated identically to a version 7 UUID with
//! the exception that: rand_b/custom_c is generated from the high 62 bits of
//! the SHA-1 hash of the FQHN string".
#![cfg(all(feature = "native", feature = "vcon"))]

use std::path::{Path, PathBuf};
use std::process::Command;

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
const CALL: &str = "call_id == '1-1966@10.0.2.20'";
const DOMAIN: &str = "pbx.example.com";
/// Octets 8 to 15 of every uuid minted under [`DOMAIN`]: the variant bits
/// `10` over the high 62 bits of SHA-1("pbx.example.com"), which is
/// `fba27a02fa3e7e3d...`. Computed outside this crate, with Python's
/// `hashlib.sha1`, so the expectation does not share code with the exporter.
const DOMAIN_OCTETS_8_TO_15: &str = "bee89e80be8f9f8f";

/// Run the binary over [`CAPTURE`] with `config` as its config file.
fn run(config: &str, home: &Path) -> Result<std::process::Output, TestError> {
    let path = home.join("rules.toml");
    std::fs::write(&path, config)?;
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            CAPTURE,
            "--no-cli-print",
            "--node-name",
            "pin-node",
        ])
        .arg("--config")
        .arg(&path)
        .env("HOME", home)
        .output()?)
}

/// A rule writing [`CALL`] to `dir`.
fn rule(dir: &Path) -> String {
    format!(
        "[[vcon.rule]]\nname = \"one\"\nwhen = \"{CALL}\"\ndir = \"{}\"\n",
        dir.display()
    )
}

/// The one container a run wrote to `dir`.
fn container(dir: &Path) -> Result<serde_json::Value, TestError> {
    let files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    assert_eq!(files.len(), 1, "one container: {files:?}");
    Ok(serde_json::from_slice(&std::fs::read(&files[0])?)?)
}

/// The 32 hex digits of a canonical uuid, hyphens removed.
fn hex_of(uuid: &str) -> String {
    uuid.chars().filter(|c| *c != '-').collect()
}

/// The uuid of the container written for [`CALL`] by a run with `section`
/// as its `[vcon]` body.
fn uuid_with(section: &str) -> Result<(String, serde_json::Value), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let out = run(&format!("[vcon]\n{section}\n\n{}", rule(&dir)), home.path())?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value = container(&dir)?;
    let uuid = value["uuid"].as_str().ok_or("a uuid")?.to_owned();
    Ok((uuid, value))
}

/// Each field of the section 4.1.2 layout, checked on its own: version 8,
/// variant `10`, the 48-bit timestamp equal to the call's start in
/// milliseconds, and the 62 bits after the variant equal to the high 62 bits
/// of SHA-1 over the domain, recomputed here.
#[test]
fn a_uuid_domain_container_follows_the_section_4_1_2_layout() -> Result<(), TestError> {
    let (uuid, value) = uuid_with(&format!("uuid_domain = \"{DOMAIN}\""))?;
    let hex = hex_of(&uuid);
    assert_eq!(hex.len(), 32, "{uuid}");

    assert_eq!(
        &hex[12..13],
        "8",
        "version 8 (RFC 9562 section 4.2): {uuid}"
    );
    let octet8 = u8::from_str_radix(&hex[16..18], 16)?;
    assert_eq!(
        octet8 >> 6,
        0b10,
        "variant 10 (RFC 9562 section 4.1): {uuid}"
    );

    let start = value["dialog"][0]["start"]
        .as_str()
        .ok_or("the dialog's start")?;
    let start_ms = chrono::DateTime::parse_from_rfc3339(start)?.timestamp_millis();
    assert_eq!(
        i64::from_str_radix(&hex[..12], 16)?,
        start_ms,
        "the 48-bit timestamp is the call's start in milliseconds ({start}): {uuid}"
    );

    let digest = <sha1_oaep::Sha1 as sha1_oaep::Digest>::digest(DOMAIN.as_bytes());
    let mut top = [0u8; 8];
    top.copy_from_slice(&digest[..8]);
    let custom_c = u64::from_be_bytes(top) >> 2;
    let expected = format!("{:016x}", (0b10_u64 << 62) | custom_c);
    assert_eq!(&hex[16..], expected, "rand_b/custom_c: {uuid}");
    assert_eq!(&hex[16..], DOMAIN_OCTETS_8_TO_15, "the out-of-tree value");
    Ok(())
}

/// Case and a trailing dot do not make a second domain: DNS names compare
/// without regard to case, and `pbx.example.com.` is the same name.
#[test]
fn a_uuid_domain_is_hashed_in_one_spelling() -> Result<(), TestError> {
    let (a, _) = uuid_with(&format!("uuid_domain = \"{DOMAIN}\""))?;
    let (b, _) = uuid_with("uuid_domain = \"PBX.Example.COM.\"")?;
    assert_eq!(a, b);
    Ok(())
}

/// Two runs over one capture write one uuid: the domain mode keeps the
/// determinism the default has.
#[test]
fn a_uuid_domain_run_is_reproducible() -> Result<(), TestError> {
    let (a, _) = uuid_with(&format!("uuid_domain = \"{DOMAIN}\""))?;
    let (b, _) = uuid_with(&format!("uuid_domain = \"{DOMAIN}\""))?;
    assert_eq!(a, b);
    Ok(())
}

/// Without `uuid_domain` the uuid is the one releases before the key wrote:
/// its last 62 bits are not the domain's. The first 64 bits (timestamp,
/// version and `rand_a`) are the same in both modes for a call that met no
/// other call in its millisecond, because both modes seed `rand_a` the same
/// way.
#[test]
fn without_uuid_domain_the_uuid_is_unchanged() -> Result<(), TestError> {
    let (plain, _) = uuid_with("")?;
    let (domain, _) = uuid_with(&format!("uuid_domain = \"{DOMAIN}\""))?;
    let (plain, domain) = (hex_of(&plain), hex_of(&domain));
    assert_ne!(&plain[16..], DOMAIN_OCTETS_8_TO_15);
    assert_eq!(&plain[..16], &domain[..16]);
    Ok(())
}

/// A sealing rule's `sealed_updates = "new-uuid"` chain under a domain: each
/// later instance keeps the first one's timestamp and the domain's 62 bits,
/// the instances differ from each other, and the chain is the same when it
/// is computed again (which is how a later instance names the one before it
/// in `amended`).
///
/// In-process, because a chain needs several writes of one live call. This
/// test binary declares the domain once for its whole process, as the
/// shipped binary does at startup; the tests above run the binary and do not
/// read the declaration.
#[test]
fn a_new_uuid_chain_under_a_domain_keeps_the_layout() -> Result<(), TestError> {
    use sipnab::output::vcon::{UuidDomain, revision_uuid, set_uuid_domain};
    set_uuid_domain(UuidDomain::new(DOMAIN)?);

    let base = "019a2b3c-4d5e-8123-8456-789abcdef012";
    assert_eq!(revision_uuid(base, 0), base, "revision 0 is the first");
    let chain: Vec<String> = (0..6).map(|n| revision_uuid(base, n)).collect();
    for (i, id) in chain.iter().enumerate().skip(1) {
        let hex = hex_of(id);
        assert_eq!(&hex[..12], &hex_of(base)[..12], "timestamp kept: {id}");
        assert_eq!(&hex[12..13], "8", "version 8: {id}");
        assert_eq!(&hex[16..], DOMAIN_OCTETS_8_TO_15, "the domain's bits: {id}");
        for other in &chain[..i] {
            assert_ne!(id, other, "two instances share a uuid");
        }
    }
    assert_eq!(
        chain,
        (0..6).map(|n| revision_uuid(base, n)).collect::<Vec<_>>(),
        "the amended pointer recomputes the uuid it names"
    );
    Ok(())
}

/// A value that is not a fully qualified host name is refused at startup,
/// naming the key, and nothing is written.
#[test]
fn a_uuid_domain_that_is_not_a_host_name_is_refused() -> Result<(), TestError> {
    for bad in [
        "",
        "pbx",
        "10.0.0.1",
        "under_score.example.com",
        "-pbx.example.com",
        "pbx-.example.com",
        "pbx..example.com",
        "pbx.example.com..",
        "*.example.com",
        "pbx.example.com/x",
        "p\u{e9}x.example.com",
    ] {
        let home = tempfile::tempdir()?;
        let dir = home.path().join("out");
        let config = format!("[vcon]\nuuid_domain = \"{bad}\"\n\n{}", rule(&dir));
        let out = run(&config, home.path())?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{bad:?}: {stderr}");
        assert!(
            stderr.contains("[vcon] uuid_domain"),
            "{bad:?}: names the key: {stderr}"
        );
        assert!(!dir.exists(), "{bad:?}: nothing written");
    }
    // 64 characters in one label, and 254 in the name, are each one too many.
    for bad in [
        format!("{}.example.com", "a".repeat(64)),
        format!(
            "{}.com",
            [
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(58)
            ]
            .join(".")
        ),
    ] {
        let home = tempfile::tempdir()?;
        let dir = home.path().join("out");
        let config = format!("[vcon]\nuuid_domain = \"{bad}\"\n\n{}", rule(&dir));
        let out = run(&config, home.path())?;
        assert_eq!(out.status.code(), Some(1), "{bad}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("[vcon] uuid_domain"));
    }
    Ok(())
}
