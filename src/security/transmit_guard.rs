// SPDX-License-Identifier: MIT OR Apache-2.0

//! sipnab transmits only while it is watching a live source.
//!
//! Almost everything sipnab does is passive: it reads packets and reports on
//! them. The scanner-kill path is the one exception — it answers a detected
//! scanner with a real SIP response on a real socket. That is defensible while
//! watching a live interface: the operator owns the network, the addresses are
//! current, and the scanner is there now.
//!
//! Applied to a capture FILE it is indefensible. `-I customer.pcap` is
//! archaeology. The addresses in it belonged to somebody at some point in the
//! past; they may have been reassigned since, they are usually not reachable
//! from the analyst's laptop in any meaningful sense, and the third parties they
//! do reach have nothing whatsoever to do with the analysis. An analyst who
//! opens a customer capture with `--kill-scanner` in their shell history emits
//! SIP at that customer's production endpoints, or at arbitrary internet hosts
//! recorded in a forensic capture, and nothing in `-I file.pcap` suggests the
//! tool sends anything at all. The damage is done before any output is read.
//!
//! # Why a type and not a check
//!
//! The failure is silent and irreversible, so it must not depend on anyone
//! remembering. [`TransmitPermit`] has a private field, so the only way to
//! obtain one anywhere in the crate is [`TransmitPermit::for_source`], which
//! inspects the capture source. Every function in the kill path that reaches a
//! socket takes one by reference. A new call site therefore cannot compile a
//! send without first proving, from the capture source, that the run is live —
//! there is no code path to forget, and no flag to get wrong.
//!
//! That is deliberately paired with a wiring-time refusal (`app::bootstrap`
//! declines to spawn the kill worker at all, and says why): the type is what
//! makes the guarantee, and the message is what tells the operator their
//! defence is not armed. Neither substitutes for the other — a type-only guard
//! leaves someone believing the kill fired, and a message-only guard is one
//! forgetful call site away from being no guard at all.
//!
//! # This permit is not the whole inventory
//!
//! Read on its own, [`TransmitPermit`] reads like the complete answer to "what
//! can put a packet on the network". It is not, and the second answer is a
//! different question rather than a hole in this one.
//!
//! `--hep-send <ADDR>` exports captured SIP to a collector **the operator
//! named on the command line**. That destination never comes out of a packet,
//! so the reasoning above does not apply to it: exporting an archived capture
//! into a Homer instance is a supported workflow, and this permit deliberately
//! does not gate it. It has its own type — `capture::hep::HepExportPermit`,
//! obtainable only from a `capture::hep::OperatorDestination`, which has no
//! constructor taking an address read out of captured traffic — and its own
//! operator-facing message, `capture::hep::file_export_notice`, which says
//! before the first packet is read that a capture FILE's contents are what
//! leaves.
//!
//! The two never convert into each other, in either direction. Watching a live
//! source does not license exporting to an operator's collector, and an
//! operator naming a collector does not license answering a scanner recorded
//! in a file. `docs/design/outbound-transmit-capability.md` records why
//! collapsing them would lose that distinction with no compile error to mark
//! it.

use crate::capture::CaptureSource;

/// Proof that this run's packets come from a live source, and therefore that
/// sipnab may put a packet back on the network they arrived from.
///
/// Constructible only by [`Self::for_source`]; the unit field is private so no
/// other module can conjure one. Passing it by reference into a send function
/// is what makes "offline never transmits" a property of the type system
/// rather than of a check somebody has to remember to write.
#[derive(Debug, Clone, Copy)]
pub struct TransmitPermit(());

impl TransmitPermit {
    /// Grant permission to transmit when `source` is live, refuse when it is a
    /// capture file.
    ///
    /// `Live` is the interface case the kill path was designed for. `Hep` is
    /// also real time — packets arrive over a socket as they happen — so the
    /// addresses are current and the existing, narrower HEP gate
    /// ([`crate::security::scanner_kill::kill_response_eligible`], which
    /// requires `--hep-allow-kill` because HEP inner addresses are
    /// sender-asserted) stays the control that applies there. `File` is the
    /// case with no defence: historical addresses, uninvolved third parties.
    pub fn for_source(source: &CaptureSource) -> Option<Self> {
        match source {
            CaptureSource::Live { .. } | CaptureSource::Hep { .. } => Some(Self(())),
            CaptureSource::File { .. } => None,
        }
    }
}

/// The message an operator sees when they asked for a transmitting feature and
/// the run is reading a file.
///
/// It has to name the flag, say what will happen instead, and say how to get
/// what they asked for — an operator who believes their scanner defence is
/// armed when it is not is the second failure this whole guard exists to
/// avoid.
///
/// # Arguments
///
/// * `feature` — the flag(s) the operator used, named as they typed them.
pub fn offline_refusal(feature: &str) -> String {
    format!(
        "{feature} sends SIP responses to the addresses in the traffic, but \
         this run is reading a capture FILE — offline analysis never transmits. \
         Those addresses are historical: they may have been reassigned, they \
         belong to third parties who are not part of this analysis, and they \
         are not on your network. Detection, alerting and reporting still run; \
         capture live with -d <device> to arm the response."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file source yields no permit; live and HEP sources do.
    #[test]
    fn only_live_sources_may_transmit() {
        let file = CaptureSource::File {
            paths: vec![std::path::PathBuf::from("/tmp/evidence.pcap")],
        };
        assert!(
            TransmitPermit::for_source(&file).is_none(),
            "reading a capture file must never grant permission to transmit"
        );

        let live = CaptureSource::Live {
            device: "eth0".to_string(),
        };
        assert!(TransmitPermit::for_source(&live).is_some());

        let hep = CaptureSource::Hep {
            bind_addr: "127.0.0.1:9060".to_string(),
            #[cfg(feature = "hep")]
            allowlist: Vec::new(),
            rate_limit: 0,
            per_peer_rate_limit: 0,
            max_tracked_peers: crate::cli::Cli::DEFAULT_MAX_TRACKED_PEERS,
            auth_key: None,
            #[cfg(feature = "hep")]
            auth_mode: crate::cli::HepAuthMode::default(),
            #[cfg(feature = "hep")]
            hmac_window_secs: crate::capture::hep::DEFAULT_HMAC_WINDOW_SECS,
        };
        assert!(
            TransmitPermit::for_source(&hep).is_some(),
            "HEP is a real-time source; the narrower --hep-allow-kill gate \
             governs it, not this one"
        );
    }

    /// The refusal names the flag and says what happens instead.
    #[test]
    fn refusal_message_names_the_flag_and_the_behaviour() {
        let msg = offline_refusal("--kill-scanner");
        assert!(msg.contains("--kill-scanner"));
        assert!(msg.contains("offline analysis never transmits"));
        assert!(msg.contains("-d <device>"), "must say how to arm it");
    }
}
