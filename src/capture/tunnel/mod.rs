// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tunnel and label-stack decapsulators.
//!
//! Each submodule turns one encapsulation into an offset: given the frame
//! bytes and the offset where that encapsulation's header begins, it reports
//! where the thing *inside* starts. None of them parse the inner packet —
//! `parse.rs` owns that walk and its depth limit — so a decapsulator is a pure
//! bounds-checked function over a byte slice and is testable in isolation.
//!
//! # Why this exists
//!
//! sipnab's failure mode for an encapsulation it did not understand used to be
//! a confident zero: a capture full of INVITEs reported as "No SIP traffic
//! found", because the frames were PPPoE- or MPLS-wrapped and the walk stopped
//! at an EtherType it did not recognize. Carrier and mobile-core traffic is
//! routinely wrapped — MPLS in the core, GTP-U on the mobile side, VXLAN in the
//! data center — so "the operator can just capture somewhere else" is not an
//! answer when the wrapped segment is the only place the problem is visible.
//!
//! # The hazard that governs every decoder here
//!
//! Over-eager decapsulation is worse than the silence it replaces. A silent
//! drop loses a call; a false decap **invents** one, complete with addresses
//! and ports that were never on the wire, and there is nothing in the output to
//! suggest the flow is fictional.
//!
//! The port-keyed tunnels are where this bites. UDP port numbers are not a
//! protocol identity: 4789 or 2152 can appear as the *ephemeral source* port of
//! an ordinary RTP stream, and reading that RTP payload as a VXLAN or GTP-U
//! header yields a plausible-looking inner packet built from voice samples. So
//! every decoder in this module MUST validate structurally — reserved bits,
//! version fields, flag/length self-consistency, and the shape of the first
//! inner header — and return `None` the moment anything disagrees. When the
//! choice is between missing a tunnel and fabricating a flow, miss the tunnel:
//! the caller now counts and reports what it could not decode, so a miss is
//! visible, whereas a fabrication is not.
//!
//! # Registry note
//!
//! EtherTypes are assigned by the **IEEE Registration Authority**, not IANA —
//! RFC 9542 says so explicitly, and IANA's `ieee-802-numbers` registry is
//! informational. The IEEE RA public listing is authoritative for the *value*,
//! but it is not error-free: as fetched on 2026-08-04 it gives `0x8848` the
//! text "8847: MPLS ... - unicast" — the `0x8847` entry duplicated, wrong
//! identifier and wrong cast — where RFC 5332 assigns it to MPLS with an
//! upstream-assigned label. Where the two disagree, the current RFC wins.
//!
//! Separately, and less severely, the listing cites `draft-ietf-sfc-nsh-18`
//! for `0x894F` eight years after that draft became RFC 8300. That one is
//! **stale rather than wrong** — the draft and the RFC define the same header
//! — and the two cases should not be filed together: one misstates a protocol,
//! the other merely names a superseded document. See `nsh.rs`, where the
//! difference was previously overstated.

pub(crate) mod l2;
pub(crate) mod mpls;
pub(crate) mod nsh;
pub(crate) mod udp;

/// What a decapsulator found inside a tunnel header.
///
/// Offsets are absolute within the frame slice handed to the decapsulator, so
/// a caller never has to remember which base a given decoder measured from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inner {
    /// An IP packet (v4 or v6 — the caller reads the version nibble) begins
    /// at this offset.
    Ip(usize),
    /// A complete Ethernet II frame, starting at its destination MAC, begins
    /// at this offset. Produced by the L2 tunnels (VXLAN, GRE-TEB, NSH with
    /// next-protocol Ethernet), whose payload is a frame rather than a packet.
    Ethernet(usize),
    /// The encapsulation was recognized and its header validated, but the
    /// payload cannot be decoded — it is encrypted, or otherwise opaque.
    ///
    /// This is deliberately NOT an error. "MACsec-encrypted payload" is a
    /// diagnosis an operator can act on; a frame that merely vanished is not.
    /// The string is a short static label for the reporting layer.
    Opaque(&'static str),
}
