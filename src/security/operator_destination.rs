// SPDX-License-Identifier: MIT OR Apache-2.0

//! A destination the operator named: the one input every capability that
//! originates traffic at an address of the operator's choosing takes.
//!
//! It lived in `capture::hep` while HEP export was its only caller. The live
//! RTP fork of `[[vcon.rule]] live_rtp` is the second, so it lives here now,
//! as section 3.1 of `docs/design/outbound-transmit-capability.md` asks, and
//! `capture::hep` re-exports it.

/// A destination the **operator** named — on the command line or in a
/// configuration file — for sipnab to originate traffic at.
///
/// [`from_cli_flag`](Self::from_cli_flag) is the only constructor, and the
/// omissions are the design: there is deliberately no `From<IpAddr>`, no
/// `From<SocketAddr>`, no constructor taking a captured packet, a HEP packet
/// or a parsed SIP message. A future call site that wants to send to an
/// address it read out of the capture cannot express it, because there is no
/// function to call — the same trick
/// `crate::security::transmit_guard::TransmitPermit`'s private field plays
/// on the capture *source*, applied here to the *destination*.
///
/// That distinction is the whole point. "The operator named this collector"
/// licenses sending them the capture. It licenses nothing about the addresses
/// inside the capture, and the type is what keeps those two apart when the
/// next exporter is written.
#[derive(Debug, Clone)]
pub struct OperatorDestination {
    /// The flag or config key the value arrived on, quoted back in
    /// operator-facing text.
    flag: &'static str,
    /// The destination as the operator wrote it (`host:port`), unresolved.
    value: String,
}

impl OperatorDestination {
    /// Record a destination the operator supplied through `flag`.
    ///
    /// `value` must come from a command-line argument or a configuration
    /// file. Passing an address formatted out of captured traffic would defeat
    /// the type, and is the one misuse it cannot detect — which is why no
    /// constructor accepts an address type in the first place.
    ///
    /// # Arguments
    ///
    /// * `flag` — the flag or config key the operator wrote, such as
    ///   `--hep-send`.
    /// * `value` — the destination they gave it, in `host:port` form.
    pub fn from_cli_flag(flag: &'static str, value: &str) -> Self {
        Self {
            flag,
            value: value.to_string(),
        }
    }

    /// The flag this destination arrived on.
    pub fn flag(&self) -> &'static str {
        self.flag
    }

    /// The destination as the operator wrote it, unresolved.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}
