// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network interface auto-detection for live capture.
//!
//! When no `-d` or `-I` flag is provided, sipnab auto-detects a suitable
//! network interface, so a zero-argument start is useful.

use anyhow::Result;

/// Find the default capture device.
///
/// On Linux, defaults to the "any" pseudo-device which captures on ALL
/// interfaces (including loopback). This is the useful default — SIP
/// traffic may be on any interface, especially loopback for local proxies.
///
/// On macOS/BSD, uses pcap's default device (based on routing table),
/// then falls back to the first non-loopback interface.
///
/// # Returns
///
/// The name of the selected capture device (always `"any"` on Linux).
///
/// # Errors
///
/// On non-Linux platforms, returns an error when no device can be found —
/// either because none exist / privileges are insufficient (with a
/// `sudo` hint) or because only loopback devices exist (listing the
/// available names).
///
/// # Side effects
///
/// On non-Linux platforms, queries libpcap for the default device and the
/// full device list (system calls into the OS capture subsystem). No I/O
/// on Linux.
pub fn find_default_device() -> Result<String> {
    // On Linux, "any" captures all interfaces, which is what we want.
    // SIP servers often listen on loopback, so capturing only eth0 misses traffic.
    if cfg!(target_os = "linux") {
        return Ok("any".to_string());
    }

    use pcap::Device;

    // macOS/BSD: use pcap's default device (based on routing table).
    if let Ok(Some(dev)) = Device::lookup()
        && !dev.name.is_empty()
    {
        return Ok(dev.name);
    }

    // Fall back: first non-loopback device from the full list.
    let devices: Vec<String> = Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect();
    if let Some(name) = first_non_loopback(&devices) {
        return Ok(name.to_string());
    }

    // Nothing found — build a helpful error message.
    Err(no_device_error(&list_devices()))
}

/// List all available capture device names.
///
/// Returns an empty vec if listing fails (e.g., insufficient privileges).
///
/// # Side effects
///
/// Queries libpcap for the system's capture device list (system calls into
/// the OS capture subsystem); errors are swallowed into the empty result.
pub fn list_devices() -> Vec<String> {
    pcap::Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect()
}

/// Parse and validate a user-supplied interface selection for multi-device
/// capture (the `-d eth0,docker0 --multi-device` form).
///
/// Splits on commas, trims surrounding whitespace from each entry, and:
/// - rejects an empty or whitespace-only spec (no interface selected),
/// - rejects empty entries from stray/doubled/leading/trailing commas,
/// - rejects names containing an embedded NUL byte (it would silently
///   truncate when handed to libpcap's C string API),
/// - removes duplicates while preserving first-seen order.
///
/// Otherwise-unusual names (backslashes, colons, dots — as in Windows NPF
/// device paths) are passed through unchanged; whether the interface actually
/// exists is left to the capture layer, which produces a precise OS error.
///
/// # Arguments
///
/// * `spec` — the raw comma-separated interface list as typed by the user
///   (e.g. `"eth0,docker0"`).
///
/// # Returns
///
/// The validated, deduplicated interface names in first-seen order.
///
/// # Errors
///
/// Returns an error for an empty/whitespace-only spec, for an empty entry
/// produced by a stray comma, or for a name containing an embedded NUL.
pub fn parse_device_list(spec: &str) -> Result<Vec<String>> {
    if spec.trim().is_empty() {
        anyhow::bail!("no interface specified: device list is empty");
    }

    let mut out: Vec<String> = Vec::new();
    for (idx, raw) in spec.split(',').enumerate() {
        let name = raw.trim();
        if name.is_empty() {
            anyhow::bail!(
                "empty interface name at position {} in device list '{}' \
                 (check for a stray, doubled, leading, or trailing comma)",
                idx + 1,
                spec
            );
        }
        if name.contains('\0') {
            anyhow::bail!(
                "interface name '{}' contains an embedded NUL byte",
                name.escape_default()
            );
        }
        if !out.iter().any(|d| d == name) {
            out.push(name.to_string());
        }
    }

    Ok(out)
}

/// The first device in `names` that is not a loopback interface.
///
/// Both spellings are skipped: `lo` on Linux, `lo0` on macOS and the BSDs.
/// Separate from [`find_default_device`] because that function answers `any`
/// on Linux before it gets here, so on the platform CI runs this would
/// otherwise never execute.
fn first_non_loopback(names: &[String]) -> Option<&str> {
    names
        .iter()
        .map(String::as_str)
        .find(|name| *name != "lo" && *name != "lo0")
}

/// The error for "no suitable device", given the devices that do exist.
///
/// An empty list usually means insufficient privileges, so it says so; a list
/// of loopbacks is shown, with the first suggested explicitly.
fn no_device_error(names: &[String]) -> anyhow::Error {
    match names.first() {
        None => anyhow::anyhow!(
            "No capture device found. Are you running with sufficient privileges?\n\
             Try: sudo sipnab"
        ),
        Some(first) => anyhow::anyhow!(
            "No suitable capture device found. Available devices: {}\n\
             Try: sipnab -d {}",
            names.join(", "),
            first
        ),
    }
}

/// Tests for device auto-detection (environment-tolerant, since CI may
/// lack pcap privileges) and for `parse_device_list` validation.
#[cfg(test)]
mod tests {
    use super::*;

    /// `list_devices` returns well-formed, deterministic device names. The
    /// list may be empty in sandboxed CI (no pcap privileges), but whatever it
    /// returns must honor the contract.
    #[test]
    fn list_devices_returns_vec() {
        let devs = list_devices();
        tracing::info!("Available devices: {:?}", devs);

        // Contract: libpcap never yields an empty interface name; an empty
        // name would silently open the default/"any" device. Vacuously true on
        // a deviceless CI box, but catches a real regression on a host with
        // NICs (e.g. a mapping bug that emitted a blank name).
        for name in &devs {
            assert!(!name.is_empty(), "device name must not be empty: {devs:?}");
        }

        // The list is a pure query of the OS device table: two back-to-back
        // calls must agree. This fails if `list_devices` ever became
        // non-idempotent (e.g. draining a shared iterator so the second call
        // came back empty on a host that has interfaces).
        let again = list_devices();
        assert_eq!(devs, again, "list_devices must be deterministic");
    }

    /// `find_default_device` yields a non-empty name, or one of the known
    /// no-device/permission errors when the environment blocks pcap.
    #[test]
    fn find_default_device_returns_non_empty() {
        // This test may fail in heavily sandboxed CI (no pcap permissions).
        // That's acceptable — the function itself is correct; the OS blocks it.
        match find_default_device() {
            Ok(name) => {
                assert!(!name.is_empty(), "Device name should not be empty");
            }
            Err(e) => {
                // Permission denied or no devices is fine in CI.
                let msg = format!("{e}");
                assert!(
                    msg.contains("No capture device")
                        || msg.contains("No suitable capture device")
                        || msg.contains("Permission"),
                    "Unexpected error: {msg}"
                );
            }
        }
    }

    /// The headline contract: with no interface selected, Linux must capture
    /// from ALL interfaces via the "any" pseudo-device (not a single NIC).
    #[cfg(target_os = "linux")]
    #[test]
    fn default_device_is_all_interfaces_on_linux() {
        let dev = find_default_device().expect("Linux default is always 'any'");
        assert_eq!(
            dev, "any",
            "Linux default capture must be the 'any' pseudo-device (all interfaces)"
        );
    }

    // ── parse_device_list: selected-interface parsing/validation ─────────

    /// A single interface name parses to a one-element list.
    #[test]
    fn device_list_single() {
        assert_eq!(parse_device_list("eth0").unwrap(), vec!["eth0"]);
    }

    /// Multiple comma-separated names parse in the order given.
    #[test]
    fn device_list_multiple_in_order() {
        assert_eq!(
            parse_device_list("eth0,docker0,lo").unwrap(),
            vec!["eth0", "docker0", "lo"]
        );
    }

    /// Spaces and tabs around entries are trimmed away.
    #[test]
    fn device_list_trims_surrounding_whitespace() {
        assert_eq!(
            parse_device_list("  eth0 ,\tdocker0  ").unwrap(),
            vec!["eth0", "docker0"]
        );
    }

    /// Repeated names are deduplicated, keeping first-seen order.
    #[test]
    fn device_list_dedups_preserving_first_seen_order() {
        assert_eq!(
            parse_device_list("eth0,docker0,eth0,lo,docker0").unwrap(),
            vec!["eth0", "docker0", "lo"]
        );
    }

    // ── Failure / adversarial cases ──────────────────────────────────────

    /// An empty spec is rejected with an "empty" error message.
    #[test]
    fn device_list_rejects_empty_string() {
        let err = parse_device_list("").unwrap_err().to_string();
        assert!(err.contains("empty"), "got: {err}");
    }

    /// A spec containing only whitespace is rejected.
    #[test]
    fn device_list_rejects_whitespace_only() {
        assert!(parse_device_list("   \t ").is_err());
    }

    /// A doubled comma ("eth0,,docker0") fails loudly rather than silently
    /// producing an empty interface name.
    #[test]
    fn device_list_rejects_doubled_comma() {
        // The classic typo: "eth0,,docker0" must fail loudly, not silently
        // try to open an interface named "".
        let err = parse_device_list("eth0,,docker0").unwrap_err().to_string();
        assert!(err.contains("empty interface name"), "got: {err}");
    }

    /// A leading comma yields an empty first entry and is rejected.
    #[test]
    fn device_list_rejects_leading_comma() {
        assert!(parse_device_list(",eth0").is_err());
    }

    /// A trailing comma yields an empty last entry and is rejected.
    #[test]
    fn device_list_rejects_trailing_comma() {
        assert!(parse_device_list("eth0,").is_err());
    }

    /// A spec that is only a comma has no valid entries and is rejected.
    #[test]
    fn device_list_rejects_bare_comma() {
        assert!(parse_device_list(",").is_err());
    }

    /// A name with an embedded NUL is rejected (it would truncate at the
    /// libpcap C-string boundary).
    #[test]
    fn device_list_rejects_embedded_nul() {
        // A NUL would truncate when passed to libpcap's C API — reject it
        // rather than silently capture on a different (or no) interface.
        let err = parse_device_list("eth0\0evil").unwrap_err().to_string();
        assert!(err.contains("NUL"), "got: {err}");
    }

    /// An entry consisting only of a NUL byte is rejected.
    #[test]
    fn device_list_rejects_nul_only_entry() {
        assert!(parse_device_list("eth0,\0,docker0").is_err());
    }

    /// Platform-specific names with backslashes/dots/braces (e.g. Windows
    /// NPF paths) pass through unmodified.
    #[test]
    fn device_list_preserves_unusual_but_valid_names() {
        // Backslashes/dots/colons appear in real capture device names on some
        // platforms (e.g. Windows "\\Device\\NPF_{...}"); they must pass through.
        assert_eq!(
            parse_device_list(r"\Device\NPF_{abc},en0.1").unwrap(),
            vec![r"\Device\NPF_{abc}", "en0.1"]
        );
    }

    // ── The non-Linux fallback, as data ──────────────────────────────────
    //
    // On Linux `find_default_device` answers `any` before reaching any of
    // this, so the fallback runs only on macOS/BSD. Its two decisions take
    // the device list as an argument, so they are pinned here on every host.

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// The first device that is not loopback wins, in the order listed;
    /// both loopback spellings (`lo`, `lo0`) are skipped.
    #[test]
    fn the_fallback_takes_the_first_device_that_is_not_loopback() {
        assert_eq!(
            first_non_loopback(&names(&["lo", "eth0", "wlan0"])),
            Some("eth0")
        );
        assert_eq!(first_non_loopback(&names(&["lo0", "en0"])), Some("en0"));
        assert_eq!(first_non_loopback(&names(&["lo", "lo0"])), None);
        assert_eq!(first_non_loopback(&[]), None);
    }

    /// No devices at all points at privileges; only loopback lists what
    /// exists and suggests the first of it.
    #[test]
    fn the_no_device_error_says_why_and_what_to_try() {
        let none = no_device_error(&[]).to_string();
        assert!(none.starts_with("No capture device found."), "{none}");
        assert!(none.contains("Try: sudo sipnab"), "{none}");

        let only_loopback = no_device_error(&names(&["lo", "lo0"])).to_string();
        assert!(
            only_loopback
                .starts_with("No suitable capture device found. Available devices: lo, lo0"),
            "{only_loopback}"
        );
        assert!(
            only_loopback.ends_with("Try: sipnab -d lo"),
            "{only_loopback}"
        );
    }
}
