// SPDX-License-Identifier: MIT OR Apache-2.0

//! How `build.rs` builds the eBPF kernel half, as pure functions of their
//! inputs.
//!
//! Shared by `build.rs` and `tests/reproducible_build_test.rs` through
//! `#[path]`, so the rule the build uses is the rule the test drives.

/// The `channel` of a `rust-toolchain.toml`, from its `[toolchain]` table.
///
/// `bpf/rust-toolchain.toml` is the one place the eBPF nightly is named. It is
/// a DATED nightly: a bare `nightly` is a different compiler every day, and the
/// object it produces is embedded in the release binary, so a release could
/// not be rebuilt bit for bit a day later. `build.rs` runs this channel, and
/// the release installs it by running `rustup toolchain install` in `bpf/`.
///
/// A deliberately small reader, not a TOML parser: the build script has no
/// dependencies, and the file is three lines this repository owns.
pub fn toolchain_channel(toml: &str) -> Option<String> {
    let mut in_toolchain = false;
    for line in toml.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_toolchain = line == "[toolchain]";
            continue;
        }
        if !in_toolchain {
            continue;
        }
        if let Some((key, value)) = line.split_once('=')
            && key.trim() == "channel"
        {
            let v = value.trim().trim_matches('"').trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// `CARGO_ENCODED_RUSTFLAGS` for the nested eBPF build.
///
/// The nested cargo gets its own flags, so the outer build's never reach it.
/// That was right for `-Dwarnings` and `-C strip=none`, which are not how the
/// kernel crate is built, and wrong for `--remap-path-prefix`: the object
/// keeps debug info for its BTF, the BTF names every source file by absolute
/// path, and the object is embedded in the release binary. So the remaps
/// `scripts/reproducible-build.sh` gave the outer build are forwarded, and
/// nothing else is.
///
/// `-Z build-std=core` compiles `core` from the nightly's `rust-src`, whose
/// path is under the builder's rustup home, so `sysroot` (the nightly's
/// `rustc --print sysroot`) is remapped to a fixed name as well.
///
/// `outer` is the outer build's `CARGO_ENCODED_RUSTFLAGS`: flags separated by
/// `\x1f`, where a remap arrives either as one `--remap-path-prefix=FROM=TO`
/// or as `--remap-path-prefix` followed by `FROM=TO`.
pub fn inner_rustflags(arch: &str, outer: &str, sysroot: Option<&str>) -> String {
    let mut flags = vec![
        format!("--cfg=bpf_target_arch=\"{arch}\""),
        // Debug info carries the BTF the loader needs to describe its maps.
        "-Cdebuginfo=2".to_string(),
        "-Clink-arg=--btf".to_string(),
    ];
    let mut outer_flags = outer.split('\x1f').filter(|f| !f.is_empty());
    while let Some(flag) = outer_flags.next() {
        if let Some(pair) = flag.strip_prefix("--remap-path-prefix=") {
            flags.push(format!("--remap-path-prefix={pair}"));
        } else if flag == "--remap-path-prefix"
            && let Some(pair) = outer_flags.next()
        {
            flags.push(format!("--remap-path-prefix={pair}"));
        }
    }
    if let Some(root) = sysroot.filter(|s| !s.is_empty()) {
        flags.push(format!("--remap-path-prefix={root}=/rustc-sysroot"));
    }
    flags.join("\x1f")
}
