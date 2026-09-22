// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which libpcap this process is running, and which alternate capture
//! backends that libpcap names.
//!
//! libpcap picks a capture backend from the device name, and sipnab passes the
//! name through: `--device netmap:eth0` reaches libpcap's netmap module only
//! when the libpcap behind the binary carries one. Which libpcap that is
//! depends on the artifact — the static musl tarballs embed their own, the gnu
//! builds and packages load the host's at runtime, the macOS builds load the
//! one macOS ships — so the only honest source is the library itself, asked at
//! runtime through `pcap_lib_version()`.
//!
//! [`running`] asks it; [`parse_banner`] reads the answer. `--version`, the
//! TUI help view, MCP `server_capabilities` and REST `GET /v1/capabilities`
//! all report [`running`], so no two surfaces can describe different
//! libraries.
//!
//! # What the banner can and cannot say
//!
//! The banner names a backend only when libpcap's own source puts it there,
//! and that is narrower than what the library can do. libpcap 1.10.6 is the
//! first release whose Linux banner mentions netmap at all; a libpcap built
//! with DPDK *beside* the native Linux capture names nothing about it (only a
//! DPDK-only build says `DPDK-only`). So [`LibpcapReport::named_backends`] is
//! what the banner names — a backend absent from it is unconfirmed, not
//! disproven — and this module never adds a backend the banner does not name.

/// Alternate capture backends a libpcap banner can name, as `(word in the
/// banner, name sipnab reports)`.
///
/// Matched as whole words, case-insensitively, so `DPDK-only` names `dpdk`
/// and a longer word that merely contains `netmap` names nothing. `zerocopy`
/// and `TPACKET_V3` are absent on purpose: both describe how the native
/// backend moves packets, not a different backend a device name selects.
const BACKEND_WORDS: &[(&str, &str)] = &[
    ("netmap", "netmap"),
    ("dpdk", "dpdk"),
    ("dag", "dag"),
    ("snf", "snf"),
];

/// What the running libpcap says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibpcapReport {
    /// `pcap_lib_version()` verbatim — the same line `strings` finds in a
    /// binary that embeds libpcap.
    pub banner: String,
    /// The version number after `libpcap version`, or `None` when the banner
    /// carries none.
    pub version: Option<String>,
    /// The alternate capture backends the banner names, lowercase, in the
    /// order `netmap`, `dpdk`, `dag`, `snf`. Empty means the banner names
    /// none — which is not proof the library has none.
    pub named_backends: Vec<&'static str>,
}

/// Read a `pcap_lib_version()` banner.
///
/// Pure: the banner is the only input, so every libpcap sipnab ships against
/// can be tested here by its exact text.
///
/// # Arguments
///
/// * `banner` — the string `pcap_lib_version()` returned.
///
/// # Returns
///
/// The banner, the version after `libpcap version` (so Npcap's
/// `Npcap version 1.79, based on libpcap version 1.10.4` yields `1.10.4`), and
/// the alternate backends it names.
#[must_use]
pub fn parse_banner(banner: &str) -> LibpcapReport {
    // Everything after `libpcap version ` up to the first space, comma or
    // parenthesis: `1.10.6` in `libpcap version 1.10.6 (64-bit time_t, …)`.
    let version = banner
        .split_once("libpcap version ")
        .map(|(_, rest)| {
            rest.split(|c: char| c.is_whitespace() || matches!(c, ',' | '(' | ')'))
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .filter(|v| !v.is_empty());
    let words: Vec<String> = banner
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let named_backends = BACKEND_WORDS
        .iter()
        .filter(|(word, _)| words.iter().any(|w| w == word))
        .map(|&(_, name)| name)
        .collect();
    LibpcapReport {
        banner: banner.to_string(),
        version,
        named_backends,
    }
}

impl LibpcapReport {
    /// One line for a human: the banner, then the backends it names.
    ///
    /// Starts with the banner itself, so `sipnab --version | grep 'libpcap
    /// version'` finds the same text the `strings` probe finds in an embedded
    /// libpcap.
    #[must_use]
    pub fn summary_line(&self) -> String {
        let backends = if self.named_backends.is_empty() {
            "none".to_string()
        } else {
            self.named_backends.join(", ")
        };
        let banner = self.banner.trim();
        if banner.is_empty() {
            format!("libpcap: no version banner; alternate capture backends named: {backends}")
        } else {
            format!("{banner}; alternate capture backends named: {backends}")
        }
    }
}

/// Ask the libpcap this process is linked against which version it is.
///
/// # Returns
///
/// [`parse_banner`] over `pcap_lib_version()`. A null pointer, which libpcap
/// never returns, reads as an empty banner rather than a crash.
///
/// # Side effects
///
/// One call into libpcap, which returns a pointer to a static string and
/// touches nothing else.
#[must_use]
pub fn running() -> LibpcapReport {
    // The `pcap` crate links libpcap but leaves this one declaration commented
    // out, so it is declared here against the same library: no `#[link]` of
    // its own, because the symbol must come from exactly the libpcap the crate
    // links — the embedded static one in a musl build, the host's in a gnu
    // one, `/usr/lib/libpcap.A.dylib` on macOS.
    unsafe extern "C" {
        fn pcap_lib_version() -> *const std::ffi::c_char;
    }
    // SAFETY: `pcap_lib_version` takes no arguments and returns a pointer to a
    // NUL-terminated string literal inside libpcap — static storage in
    // libpcap 1.10.6's `pcap-linux.c` and `pcap-bpf.c` and in Apple's
    // `pcap-bpf.c`, the three libraries sipnab's artifacts load — so the
    // pointer is valid for the whole process and nothing frees or mutates it.
    // The null check keeps a hypothetical null from reaching `CStr::from_ptr`,
    // which requires non-null; the bytes are copied out before the block ends.
    let banner = unsafe {
        let ptr = pcap_lib_version();
        if ptr.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    parse_banner(&banner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `strings` over the `sipnab` binary in the published
    /// `sipnab-0.5.183-aarch64-unknown-linux-musl.tar.gz` (checksum verified
    /// against that release's `SHA256SUMS.txt`), 2026-09-21. It is also what
    /// libpcap 1.10.6's `pcap-linux.c` builds from `"with TPACKET_V3 and
    /// netmap"` and `pcap-int.h`'s `PCAP_VERSION_STRING_WITH_ADDITIONAL_INFO`.
    const MUSL_1_10_6: &str = "libpcap version 1.10.6 (64-bit time_t, with TPACKET_V3 and netmap)";

    /// `strings` over `libpcap.so` from Debian trixie's
    /// `libpcap0.8t64_1.10.5-2_arm64.deb` — the libpcap the Docker image's
    /// `debian:trixie-slim` runtime installs — 2026-09-21.
    const DEBIAN_1_10_5: &str = "libpcap version 1.10.5 (with TPACKET_V3)";

    /// `strings` over this development host's Ubuntu
    /// `libpcap0.8t64 1.10.4-4.1ubuntu3`, 2026-09-21.
    const UBUNTU_1_10_4: &str = "libpcap version 1.10.4 (with TPACKET_V3)";

    /// What macOS's own libpcap returns, read from source rather than a
    /// running Mac: Apple's `libpcap-146` (github.com/apple-oss-distributions
    /// /libpcap, 2026-04-17) sets `PACKAGE_VERSION` to `1.10.1`, leaves
    /// `PCAP_SUPPORT_NETMAP` and `PCAP_SUPPORT_DPDK` undefined, and its
    /// `pcap-bpf.c` returns bare `PCAP_VERSION_STRING` without zerocopy. That
    /// project's Xcode build installs `libpcap.A.dylib` into `/usr/lib`, the
    /// path the published darwin binaries load (their `LC_LOAD_DYLIB`); an
    /// older macOS carries an older release of the same project.
    const MACOS_1_10_1: &str = "libpcap version 1.10.1";

    /// libpcap 1.10.6's `pcap-bpf.c`, built with netmap on a BSD.
    const BSD_ZEROCOPY_NETMAP: &str =
        "libpcap version 1.10.6 (64-bit time_t, with zerocopy and netmap support)";

    /// libpcap 1.10.6's `pcap-dpdk.c`, built DPDK-only.
    const DPDK_ONLY: &str = "libpcap version 1.10.6 (64-bit time_t, DPDK-only)";

    #[test]
    fn the_musl_banner_names_netmap_and_its_version() {
        let r = parse_banner(MUSL_1_10_6);
        assert_eq!(r.banner, MUSL_1_10_6);
        assert_eq!(r.version.as_deref(), Some("1.10.6"));
        assert_eq!(r.named_backends, vec!["netmap"]);
    }

    #[test]
    fn a_distribution_banner_names_no_alternate_backend() {
        for (banner, version) in [(DEBIAN_1_10_5, "1.10.5"), (UBUNTU_1_10_4, "1.10.4")] {
            let r = parse_banner(banner);
            assert_eq!(r.version.as_deref(), Some(version), "{banner}");
            assert!(
                r.named_backends.is_empty(),
                "{banner} names no alternate backend, and the report claimed {:?} — \
                 TPACKET_V3 is how the native Linux backend reads, not another backend",
                r.named_backends
            );
        }
    }

    #[test]
    fn the_macos_banner_is_a_bare_version() {
        let r = parse_banner(MACOS_1_10_1);
        assert_eq!(r.version.as_deref(), Some("1.10.1"));
        assert!(r.named_backends.is_empty());
    }

    #[test]
    fn zerocopy_is_not_a_backend_but_netmap_beside_it_is() {
        assert_eq!(
            parse_banner(BSD_ZEROCOPY_NETMAP).named_backends,
            vec!["netmap"]
        );
    }

    #[test]
    fn a_dpdk_only_build_names_dpdk() {
        let r = parse_banner(DPDK_ONLY);
        assert_eq!(r.version.as_deref(), Some("1.10.6"));
        assert_eq!(r.named_backends, vec!["dpdk"]);
    }

    /// A backend is a whole word. A banner carrying a longer word that
    /// contains one must not be read as naming it.
    #[test]
    fn a_backend_word_inside_a_longer_word_names_nothing() {
        let r = parse_banner("libpcap version 9.9.9 (with netmapper and dagger)");
        assert!(r.named_backends.is_empty(), "{:?}", r.named_backends);
    }

    #[test]
    fn a_wrapper_banner_reports_the_libpcap_it_is_based_on() {
        let r = parse_banner("Npcap version 1.79, based on libpcap version 1.10.4");
        assert_eq!(r.version.as_deref(), Some("1.10.4"));
    }

    #[test]
    fn an_empty_banner_claims_nothing() {
        let r = parse_banner("");
        assert_eq!(r.version, None);
        assert!(r.named_backends.is_empty());
    }

    #[test]
    fn the_summary_line_leads_with_the_banner_and_names_the_backends() {
        assert_eq!(
            parse_banner(MUSL_1_10_6).summary_line(),
            "libpcap version 1.10.6 (64-bit time_t, with TPACKET_V3 and netmap); \
             alternate capture backends named: netmap"
        );
        assert_eq!(
            parse_banner(DEBIAN_1_10_5).summary_line(),
            "libpcap version 1.10.5 (with TPACKET_V3); alternate capture backends named: none"
        );
        assert_eq!(
            parse_banner("").summary_line(),
            "libpcap: no version banner; alternate capture backends named: none"
        );
    }

    /// The FFI reaches the libpcap this test binary links, and what it
    /// reports is exactly the pure parse of its banner — one rule, not two.
    #[test]
    fn the_running_library_answers_and_is_read_by_the_same_rule() {
        let r = running();
        assert!(
            r.banner.contains("libpcap version"),
            "pcap_lib_version() returned {:?}, which is not a libpcap banner",
            r.banner
        );
        assert!(r.version.is_some(), "no version in {:?}", r.banner);
        assert_eq!(r, parse_banner(&r.banner));
    }
}
