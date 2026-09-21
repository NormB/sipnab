// SPDX-License-Identifier: MIT OR Apache-2.0

//! The netmap headers the static musl images compile libpcap against request an
//! API that a netmap kernel module built today accepts.
//!
//! Measured 2026-09-21 on a Debian 13 host, kernel 6.12.105, with a veth pair
//! in its own network namespace. The published 0.5.183 musl binary embeds a
//! libpcap built against netmap tag v13.0, which requests API 13. netmap
//! master (389daea, the only netmap that builds on that kernel — v13.0 fails
//! to compile against its `skb_frag_t`) refuses it:
//! `netmap_ioctl_legacy  Minimum supported API is 14 (requested 13)`, and
//! `--device netmap:<iface>` fails with `NIOCREGIF failed: Invalid argument`.
//! The same libpcap 1.10.6 built against master's API-14 headers captured 5 of
//! 5 SIP messages through `netmap:`. The backend was compiled in, advertised,
//! and unusable, and nothing in the tree could see it: the image gate checks
//! that `pcap-netmap.o` is in the archive, not which API it speaks.

#![cfg(feature = "full")]

use std::path::Path;

/// The lowest `NETMAP_API` netmap master accepts (`NETMAP_MIN_API` in its
/// `sys/net/netmap.h` at 389daea).
const NETMAP_MIN_API_ACCEPTED: u32 = 14;

/// The two images whose libpcap carries the netmap module.
const MUSL_IMAGES: [&str; 2] = [
    "docker/cross/Dockerfile.x86_64-unknown-linux-musl",
    "docker/cross/Dockerfile.aarch64-unknown-linux-musl",
];

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("{rel} must be readable: {e}"))
}

/// The value of `ARG <name>=<value>` in a Dockerfile, if declared.
fn arg(dockerfile: &str, name: &str) -> Option<String> {
    let prefix = format!("ARG {name}=");
    dockerfile
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix).map(str::to_string))
}

/// Each musl image declares the netmap API its pinned headers speak, and it is
/// one current netmap accepts.
#[test]
fn the_musl_images_pin_a_netmap_api_current_modules_accept() {
    for image in MUSL_IMAGES {
        let text = read(image);
        let api: u32 = arg(&text, "NETMAP_API")
            .unwrap_or_else(|| {
                panic!(
                    "{image} does not declare ARG NETMAP_API, so nothing says which netmap \
                     API its libpcap requests"
                )
            })
            .parse()
            .unwrap_or_else(|e| panic!("{image}: NETMAP_API is not a number: {e}"));
        assert!(
            api >= NETMAP_MIN_API_ACCEPTED,
            "{image} pins netmap API {api}; current netmap modules refuse anything below \
             {NETMAP_MIN_API_ACCEPTED}, so `--device netmap:` would fail on every host that \
             can build netmap today"
        );
    }
}

/// The declared API is checked against the header that arrived, so the ARG
/// cannot drift from the bytes the way a comment can.
#[test]
fn the_musl_images_check_the_fetched_header_against_the_declared_api() {
    for image in MUSL_IMAGES {
        let text = read(image);
        let checked = text.lines().any(|l| {
            l.contains("grep")
                && l.contains("NETMAP_API")
                && l.contains("${NETMAP_API}")
                && l.contains("netmap.h")
        });
        assert!(
            checked,
            "no build step in {image} greps the fetched netmap.h for ${{NETMAP_API}}; an \
             ARG nobody checks against the bytes is a comment"
        );
    }
}

/// Both images pin the same netmap: an x86_64 and an aarch64 binary of one
/// release must not speak different netmap APIs.
#[test]
fn both_musl_images_pin_the_same_netmap() {
    let pins = |image: &str| -> Vec<Option<String>> {
        let text = read(image);
        [
            "NETMAP_COMMIT",
            "NETMAP_API",
            "NETMAP_H_SHA256",
            "NETMAP_USER_H_SHA256",
            "NETMAP_LEGACY_H_SHA256",
        ]
        .iter()
        .map(|name| arg(&text, name))
        .collect()
    };
    assert_eq!(
        pins(MUSL_IMAGES[0]),
        pins(MUSL_IMAGES[1]),
        "the x86_64 and aarch64 musl images pin different netmap headers"
    );
}
