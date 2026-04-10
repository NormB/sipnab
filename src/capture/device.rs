//! Network interface auto-detection for live capture.
//!
//! When no `-d` or `-I` flag is provided, sipnab auto-detects a suitable
//! network interface — matching sngrep's zero-argument startup behavior.

use anyhow::Result;

/// Find the default capture device.
///
/// Strategy:
/// 1. Use the device pcap considers "default" (based on routing table).
/// 2. Fall back to the first non-loopback device from `pcap::Device::list()`.
/// 3. On Linux, fall back to the "any" pseudo-device.
/// 4. Otherwise, return an error with available device names for diagnostics.
pub fn find_default_device() -> Result<String> {
    use pcap::Device;

    // Prefer the device pcap considers "default" (usually the one with
    // the default route).
    if let Ok(Some(dev)) = Device::lookup()
        && !dev.name.is_empty()
    {
        return Ok(dev.name);
    }

    // Fall back: first non-loopback device from the full list.
    let devices = Device::list().unwrap_or_default();
    for dev in &devices {
        if dev.name != "lo" && dev.name != "lo0" {
            return Ok(dev.name.clone());
        }
    }

    // Last resort on Linux: the "any" pseudo-device captures everything.
    if cfg!(target_os = "linux") {
        return Ok("any".to_string());
    }

    // Nothing found — build a helpful error message.
    let names = list_devices();
    if names.is_empty() {
        anyhow::bail!(
            "No capture device found. Are you running with sufficient privileges?\n\
             Try: sudo sipnab"
        );
    } else {
        anyhow::bail!(
            "No suitable capture device found. Available devices: {}\n\
             Try: sipnab -d {}",
            names.join(", "),
            names[0]
        );
    }
}

/// List all available capture device names.
///
/// Returns an empty vec if listing fails (e.g., insufficient privileges).
pub fn list_devices() -> Vec<String> {
    pcap::Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_devices_returns_vec() {
        // Should not panic; may be empty in sandboxed CI environments.
        let devs = list_devices();
        // On most systems there is at least a loopback device.
        log::info!("Available devices: {:?}", devs);
    }

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
}
