// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network packet capture, pcap/pcapng file reading, TCP reassembly, HEP protocol,
//! and TLS decryption.
//!
//! This module coordinates live device capture, pcap file reading, and output
//! writing. It provides [`start_capture`] as the main entry point, which spawns
//! a capture thread and returns a [`CaptureHandle`] for lifecycle management.

#[cfg(feature = "native")]
pub mod atomic;
#[cfg(feature = "native")]
pub mod channel;
#[cfg(feature = "tls")]
pub mod decrypt;
#[cfg(feature = "native")]
pub mod device;
#[cfg(feature = "tls")]
pub mod dtls;
/// Kernel-side distribution of one interface across N capture sockets.
/// Capture only — see the module docs before assuming it shards processing.
#[cfg(feature = "native")]
pub mod fanout;
#[cfg(feature = "native")]
pub mod file;
#[cfg(feature = "hep")]
pub mod hep;
#[cfg(feature = "native")]
pub mod input_set;

/// Where TLS keylog bytes arrive from: a file, a FIFO, or an inherited fd.
#[cfg(feature = "tls")]
pub mod keylog_source;

#[cfg(feature = "native")]
pub mod live;
#[cfg(feature = "native")]
pub mod mapped;
/// Reading a pcapng whose interfaces disagree, which libpcap refuses.
///
/// Gated on `native` like its siblings: the decoder is `pcap-file`, which only
/// `native` pulls in. Declaring it unconditionally broke every feature
/// combination built without `native` — caught by the gate's `tls`-only and
/// `wasm` legs, not by `--all-features`, which can never see a missing feature.
#[cfg(feature = "native")]
pub mod merged;
#[cfg(feature = "native")]
pub mod output_guard;
pub mod packet;
pub mod parse;
pub mod pcap_reader;
#[cfg(feature = "native")]
pub mod pcapng_meta;
pub mod reassembly;
/// Which capture a server holds, shared by REST and MCP so both name the same
/// one. See the module docs for why it is not defined inside either server.
pub mod session;
/// Deciding what a kernel uprobe delivered may be used for.
#[cfg(target_os = "linux")]
pub mod uprobe;
// Following a frame pointer means re-reading a capture file, which is
// libpcap's job, so this shares `file`'s gate rather than inventing its own.
#[cfg(feature = "native")]
pub mod resolve;
#[cfg(feature = "tls")]
pub mod rsa_key;
#[cfg(feature = "tls")]
pub mod tls;
// Decapsulators for the wrappings carrier and data-center traffic arrives in:
// MPLS, NSH, GTP-U, VXLAN and friends. `parse` drives them; they own no walk
// of their own.
pub(crate) mod tunnel;
pub mod websocket;
#[cfg(feature = "native")]
pub mod writer;

// Live-capture sources and thread orchestration (CaptureSource / CaptureConfig
// / CaptureHandle / start_capture / start_multi_capture) live here, gated once.
#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::{
    CaptureConfig, CaptureHandle, CaptureSource, DEFAULT_BUFFER_MB, UprobeBackend, UprobeTarget,
    start_capture, start_multi_capture, stop_and_join,
};

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use smallvec::{SmallVec, smallvec};

use crate::error::CaptureError;

pub use packet::Packet;
pub use parse::ParsedPacket;

/// Raw packets handed to [`PacketProcessor::process`] since the process
/// started, exported as `sipnab_capture_packets_total`.
///
/// Process-global rather than per-processor because the parallel pipeline
/// gives every worker thread its own [`PacketProcessor`], and a scrape asks
/// about the capture, not about one worker. Relaxed ordering: this is a
/// counter read by a scrape, never a happens-before edge for other state.
static CAPTURED_PACKETS: AtomicU64 = AtomicU64::new(0);

/// Packets processed since start — the value behind
/// `sipnab_capture_packets_total`.
///
/// Counted at the head of [`PacketProcessor::process`], so it includes
/// packets that turn out to be unparseable: those were still captured, and a
/// counter that dropped them would read as a stalled capture on a link full
/// of non-IP traffic.
///
/// # Returns
///
/// Monotonic count of packets fed to the processing pipeline.
pub fn captured_packets() -> u64 {
    CAPTURED_PACKETS.load(Ordering::Relaxed)
}

// ── Frames sipnab could not decode ───────────────────────────────────
//
// sipnab's failure mode for an encapsulation it cannot read was a CONFIDENT
// ZERO. A DLT_NULL capture full of SIP produced "49 packets captured, 0 SIP
// messages, 0 RTP packets across 0 streams" and then "No SIP traffic found.",
// exit 0 — output textually IDENTICAL to a capture that was read perfectly and
// genuinely contained no SIP. The single swallow site logged the error at
// `debug!`, which is off by default, and returned an empty vector. Nothing
// counted it, so no summary, report, metric or exit code could tell the two
// apart.
//
// The counters below make "I could not read this" a fact the run reports. Three
// rules shape them, and each exists because the obvious alternative is wrong:
//
//   * **The NUMBER is the whole point.** "Unsupported link type" is useless
//     without "0"; "unknown EtherType" is useless without "0x8847". An operator
//     converts a capture, widens a filter, or files a decoder request based on
//     that number, and a reason without one names no action.
//   * **This is the hot path.** It runs once per undecodable frame, and on a
//     capture sipnab cannot read at all that is once per frame. So: no
//     allocation, no lock, no map. Fixed-slot lock-free tables of atomics,
//     merged only when a report is asked for.
//   * **ICMP is not undecodable.** `parse_packet` records the ICMP quote as
//     dialog evidence and *then* returns `CaptureError::Icmp` — the frame was
//     understood, it just produces no `ParsedPacket`. Counting it here would
//     make every capture carrying an ICMP error look partly unread, and the
//     ICMP summary already reports it.

/// Frames that reached the parser and produced no [`ParsedPacket`] because
/// sipnab could not decode them. Exact even when the per-reason tables below
/// overflow, which is why it is kept apart from them.
static UNDECODABLE_FRAMES: AtomicU64 = AtomicU64::new(0);

/// Distinct numbers each per-reason table can name before it starts reporting
/// frames as "reason lost" instead.
///
/// A capture carries a handful of undecodable link types / EtherTypes / IP
/// protocols, not hundreds, so this is sized for the real distribution rather
/// than the worst case: the cost of a miss is a linear scan of this many
/// relaxed loads on a path that only runs for frames already being discarded.
pub const UNDECODABLE_REASON_SLOTS: usize = 16;

/// Sentinel for a slot no thread has claimed. Outside every real key
/// (a DLT is an `i32`, an EtherType a `u16`, an IP protocol a `u8`).
const TALLY_EMPTY: i64 = i64::MIN;

/// Sentinel key for "the number could not be read from the frame".
/// Negative, so it cannot collide with a real EtherType or protocol number.
const TALLY_NO_NUMBER: i64 = -1;

/// Fixed-capacity, lock-free tally of `number -> frames`.
///
/// Open-addressed by linear scan and claimed by compare-exchange. A slot is
/// claimed once and never released, so a reader never sees a key change under
/// it; two threads racing on the same new key may claim two slots for it,
/// which [`UndecodableReport`] merges. Frames arriving after every slot is
/// claimed are counted in `overflow` rather than dropped — the total must stay
/// exact even when the breakdown cannot.
struct NumTally {
    /// Claimed numbers, or [`TALLY_EMPTY`].
    keys: [std::sync::atomic::AtomicI64; UNDECODABLE_REASON_SLOTS],
    /// Frames counted against the key at the same index.
    counts: [AtomicU64; UNDECODABLE_REASON_SLOTS],
    /// Frames whose number found no free slot, so its identity was lost.
    overflow: AtomicU64,
}

impl NumTally {
    /// An empty tally.
    const fn new() -> Self {
        // `[EXPR; N]` needs a `const` item for a non-`Copy` element type;
        // each repeat evaluates the initializer afresh, which is exactly the
        // separate-atomic-per-slot this wants.
        #[expect(
            clippy::declare_interior_mutable_const,
            reason = "const-item repeat is the only const way to build an array of atomics; \
                      each repetition constructs a distinct atomic, never a shared one"
        )]
        const EMPTY: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(TALLY_EMPTY);
        #[expect(
            clippy::declare_interior_mutable_const,
            reason = "as above — one fresh zeroed counter per slot"
        )]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            keys: [EMPTY; UNDECODABLE_REASON_SLOTS],
            counts: [ZERO; UNDECODABLE_REASON_SLOTS],
            overflow: AtomicU64::new(0),
        }
    }

    /// Count one frame against `key`.
    ///
    /// # Arguments
    ///
    /// * `key` — the number identifying the reason (DLT, EtherType, IP
    ///   protocol), or [`TALLY_NO_NUMBER`] when the frame did not state one.
    ///
    /// # Side effects
    ///
    /// Claims a slot for a number not seen before, or bumps `overflow` when
    /// every slot is taken. Relaxed throughout: these counters are read by a
    /// report, never as a happens-before edge for other state.
    fn bump(&self, key: i64) {
        for i in 0..UNDECODABLE_REASON_SLOTS {
            let seen = self.keys[i].load(Ordering::Relaxed);
            if seen == key {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
            if seen == TALLY_EMPTY {
                // Losing the race means another thread claimed this slot: if it
                // claimed it for the same key, count here anyway; otherwise
                // walk on.
                match self.keys[i].compare_exchange(
                    TALLY_EMPTY,
                    key,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        self.counts[i].fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(won_by) if won_by == key => {
                        self.counts[i].fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(_) => {}
                }
            }
        }
        self.overflow.fetch_add(1, Ordering::Relaxed);
    }

    /// Append this tally's non-empty slots to `out`, merging any key that a
    /// race split across two slots, and return the overflow count.
    fn collect(
        &self,
        reason_of: impl Fn(i64) -> UndecodableReason,
        out: &mut Vec<UndecodableTally>,
    ) -> u64 {
        for i in 0..UNDECODABLE_REASON_SLOTS {
            let key = self.keys[i].load(Ordering::Relaxed);
            if key == TALLY_EMPTY {
                continue;
            }
            let frames = self.counts[i].load(Ordering::Relaxed);
            if frames == 0 {
                continue; // claimed but not yet counted
            }
            let reason = reason_of(key);
            match out.iter_mut().find(|t| t.reason == reason) {
                Some(t) => t.frames += frames,
                None => out.push(UndecodableTally { reason, frames }),
            }
        }
        self.overflow.load(Ordering::Relaxed)
    }

    /// Clear every slot and the overflow count.
    fn reset(&self) {
        for i in 0..UNDECODABLE_REASON_SLOTS {
            self.keys[i].store(TALLY_EMPTY, Ordering::Relaxed);
            self.counts[i].store(0, Ordering::Relaxed);
        }
        self.overflow.store(0, Ordering::Relaxed);
    }
}

/// Frames whose pcap link type sipnab has no decoder for, by DLT number.
static UNSUPPORTED_LINK_TYPE: NumTally = NumTally::new();
/// Frames that decoded but carry no IP layer, by EtherType.
static NOT_IP: NumTally = NumTally::new();
/// Frames whose IP payload is no transport sipnab handles, by IP protocol.
static NO_TRANSPORT: NumTally = NumTally::new();
/// Frames shorter than the header they claim.
static TRUNCATED_FRAMES: AtomicU64 = AtomicU64::new(0);

/// Frames the CAPTURE truncated: `caplen < origlen`, meaning a snaplen cut the
/// frame short before sipnab ever saw it.
///
/// Deliberately NOT part of the undecodable tally, and deliberately not
/// [`TRUNCATED_FRAMES`], which counts a frame shorter than the header it
/// claims — a malformed frame. A snapped frame is not malformed and not an
/// error: it usually decodes perfectly, because a small snaplen keeps every
/// header and drops the payload, which is exactly what a signaling capture
/// wants. It is a FACT ABOUT THE CAPTURE, and the operator needs it because
/// the existing `--snaplen` warnings fire once per run and so cannot say how
/// MUCH of a capture arrived cut short. A run that decoded every packet and
/// truncated 94% of them is not a clean capture, and without this counter it
/// reported as one.
static SNAPPED_FRAMES: AtomicU64 = AtomicU64::new(0);
/// Frames a decoder rejected outright.
static DECODE_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Why one frame produced no [`ParsedPacket`], with the number that names it.
///
/// The number is not decoration. "Unsupported link type" tells an operator
/// nothing; "unsupported link type 0" tells them the file is `DLT_NULL` and
/// `editcap -T ether` will convert it. "Not IP" tells them nothing; "EtherType
/// 0x8847" tells them the span port is mirroring MPLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UndecodableReason {
    /// The pcap link type has no decoder in sipnab. Carries the DLT number.
    UnsupportedLinkType(i32),
    /// The link layer decoded and named a payload that is not IP. Carries the
    /// EtherType when the link layer states one (`None` for link types that
    /// do not, such as `DLT_RAW`, or a frame too short to reach it).
    NotIp(Option<u16>),
    /// An IP header decoded but its payload is no transport sipnab handles.
    ///
    /// Carries the protocol number from the frame's **outermost** IP header,
    /// which is the number a filter or a decoder request is written against.
    /// For a tunnel whose inner packet is the one lacking a transport that is
    /// the tunnel's own protocol (4, 41, 47) rather than the inner one —
    /// still true, and still the layer to look at first. `None` when the
    /// frame's link type puts the IP header at no fixed offset.
    NoTransport(Option<u8>),
    /// The frame is shorter than a header it claims. A snaplen or a cut
    /// capture, not a parser gap.
    Truncated,
    /// A decoder rejected the bytes.
    DecodeError,
}

impl UndecodableReason {
    /// Stable identifier for this reason, for use as a metric label value.
    ///
    /// Carries the same number the [`Display`](std::fmt::Display) form does:
    /// a label that collapsed every DLT into `unsupported_link_type` would
    /// make the series unactionable in exactly the way the sentence would.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::UnsupportedLinkType(dlt) => format!("unsupported_link_type_{dlt}"),
            Self::NotIp(Some(et)) => format!("not_ip_ethertype_0x{et:04x}"),
            Self::NotIp(None) => "not_ip_ethertype_unrecorded".to_string(),
            Self::NoTransport(Some(p)) => format!("no_transport_ip_protocol_{p}"),
            Self::NoTransport(None) => "no_transport_ip_protocol_unrecorded".to_string(),
            Self::Truncated => "truncated_frame".to_string(),
            Self::DecodeError => "decode_error".to_string(),
        }
    }
}

impl std::fmt::Display for UndecodableReason {
    /// The operator-facing sentence, always carrying the number.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedLinkType(dlt) => write!(f, "unsupported link type {dlt}"),
            Self::NotIp(Some(et)) => write!(f, "not IP (EtherType 0x{et:04X})"),
            Self::NotIp(None) => write!(f, "not IP (EtherType not recorded)"),
            Self::NoTransport(Some(p)) => write!(f, "no transport (IP protocol {p})"),
            Self::NoTransport(None) => write!(f, "no transport (IP protocol not recorded)"),
            Self::Truncated => write!(f, "truncated frame"),
            Self::DecodeError => write!(f, "decode error"),
        }
    }
}

/// Frames counted against one [`UndecodableReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UndecodableTally {
    /// Why those frames produced nothing.
    pub reason: UndecodableReason,
    /// How many frames.
    pub frames: u64,
}

/// How far forward sipnab searches for the TLS record sequence number of a
/// stream it has not yet decrypted.
///
/// A capture started against a connection that was already running joins the
/// record stream part-way through, and no TLS version puts the record number
/// on the wire. The AEAD tag makes searching for it safe, and this bounds the
/// search — so it is also the answer to "how far into an established
/// connection may a capture start and still be readable".
///
/// Lives here, beside [`TlsDecryptReport`], because the decryptor that spends
/// it and the message that quotes it to the operator must not drift apart.
pub const TLS_SEQ_LOCKON_WINDOW: u64 = 1 << 20;

// Sized from what it costs and what it buys, not from a round number that
// looked safe. Each trial is one AEAD tag verification -- roughly a
// microsecond -- and the search runs ONCE per direction per session, not per
// record, so the whole window is a one-off of about a second. It was 4096,
// which sounds generous and is about seven minutes of a trunk ticking over at
// ten records a second. A carrier that holds its TLS connection open for hours
// is far past that, and "restart the connection" is not a step an operator can
// take on live traffic: a persistent trunk stayed unreadable until the daemon
// was restarted, while a fresh-per-call carrier on the same host decrypted
// immediately. A million records is roughly a day at that rate.

/// What a run's TLS decryption actually achieved, as counts.
///
/// The sibling of [`UndecodableReport`], for the layer above the link: an
/// operator who supplies `--keylog` is told the keys loaded and then, if
/// nothing decrypts, told only that no SIP was found. Those two statements
/// are consistent with a capture that holds nothing and with a capture full
/// of SIP sipnab could not read, and the run renders them identically. These
/// counts are what let it tell the two apart.
///
/// Defined here rather than beside the decryptor so the reporting path
/// compiles in feature combinations built without `tls`, where every count is
/// simply zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TlsDecryptReport {
    /// Keylog entries loaded, whatever became of them.
    ///
    /// Separate from `sessions_with_keys` because the gap between the two is a
    /// failure of its own: a TLS 1.2 `CLIENT_RANDOM` line carries the master
    /// secret, and the server random and cipher suite that turn it into record
    /// keys are in the ServerHello. Keys can therefore arrive in full and still
    /// build no session, which has nothing to do with where they came from.
    pub keylog_entries: usize,
    /// Sessions built from the supplied key material, i.e. secrets sipnab
    /// holds and could derive record keys from.
    pub sessions_with_keys: usize,
    /// ApplicationData records offered to the decryptor.
    pub app_data_records: u64,
    /// ApplicationData records that were opened.
    pub decrypted_records: u64,
    /// Records recovered by a late replay: held because no key existed when
    /// they arrived, then opened once one did.
    pub late_recovered: u64,
    /// Records dropped from the hold before a key ever arrived, because the
    /// byte budget filled. Kept beside `late_recovered` because without it
    /// "we never had the keys" and "we had them and had already discarded the
    /// ciphertext" are the same silence.
    ///
    /// Reaches the operator through `late_hold_guidance`, which runs on
    /// successful runs as well as failed ones -- an eviction only happens on a
    /// capture that was otherwise working, so reporting it only when nothing
    /// decrypted would be reporting it never.
    pub late_evicted: u64,
    /// Records still held at the end of the run, i.e. keys that never came.
    pub late_still_held: u64,
}

/// Total ciphertext the late-keylog hold may keep across every session at once.
///
/// Defined here rather than in [`decrypt`] because the operator-facing message
/// that quotes it lives outside the `tls` feature while the enforcement lives
/// inside it. One definition, both readers -- a message naming a bound the code
/// does not enforce is worse than no message.
pub const REWIND_BUDGET_BYTES: usize = 4 * 1024 * 1024;

/// Held records per TCP direction, so one noisy direction cannot starve the
/// others out of the shared byte budget.
pub const MAX_REWIND_PER_DIRECTION: usize = 16;

/// How far behind the newest packet a held record may be before it is retired.
pub const REWIND_MAX_AGE_SECS: i64 = 5;

impl TlsDecryptReport {
    /// ApplicationData records seen and not opened.
    ///
    /// Not a loss figure. A healthy TLS 1.3 capture always leaves several of
    /// these behind: EncryptedExtensions, Certificate, CertificateVerify and
    /// both Finished messages travel in ApplicationData framing but are sealed
    /// under the HANDSHAKE traffic secrets, which sipnab does not load because
    /// they carry no application data. Treating the difference as dropped SIP
    /// would report five phantom losses on every capture that includes a
    /// handshake. Use [`Self::read_nothing`] to judge a run.
    #[must_use]
    pub fn undecrypted_records(&self) -> u64 {
        self.app_data_records.saturating_sub(self.decrypted_records)
    }

    /// Whether this run saw TLS application data and opened none of it.
    ///
    /// The one unambiguous failure: any successful decrypt proves the keys,
    /// the sequence numbers and the session matching all work, whereas none at
    /// all means the run is holding ciphertext it can say nothing about.
    #[must_use]
    pub fn read_nothing(&self) -> bool {
        self.app_data_records > 0 && self.decrypted_records == 0
    }
}

/// The TLS decryption tallies, published where a SERVER can read them.
///
/// [`TlsDecryptReport`] is built from a [`decrypt::TlsDecryptor`] that the
/// batch run owns locally, which is why it reached the CLI's end-of-run summary
/// and nothing else. A live capture serving REST or MCP has that decryptor deep
/// inside the packet loop and no handle to it, so the one number that separates
/// "this network was quiet" from "sipnab is holding ciphertext it cannot open"
/// was unavailable to both servers for the entire run.
///
/// Published as process-global atomics rather than by threading a handle, which
/// is the pattern [`undecodable_frames`] and [`snapped_frames`] already
/// establish: a monotonic count anything can read with one relaxed load and no
/// lock. The decryptor bumps these alongside its own fields.
///
/// **Monotonic and process-wide.** A test that installs several decryptors sums
/// them; assert on a DELTA rather than a figure, the same way the media-creating
/// tally is tested.
mod tls_tally {
    use std::sync::atomic::AtomicU64;

    /// Keylog entries loaded, whatever became of them.
    pub(super) static KEYLOG_ENTRIES: AtomicU64 = AtomicU64::new(0);
    /// Sessions built from that key material.
    pub(super) static SESSIONS_WITH_KEYS: AtomicU64 = AtomicU64::new(0);
    /// ApplicationData records offered to a decryptor.
    pub(super) static APP_DATA_RECORDS: AtomicU64 = AtomicU64::new(0);
    /// ApplicationData records actually opened.
    pub(super) static DECRYPTED_RECORDS: AtomicU64 = AtomicU64::new(0);
    /// Records held for a missing key and opened once one arrived.
    pub(super) static LATE_RECOVERED: AtomicU64 = AtomicU64::new(0);
    /// Records dropped from the hold before any key arrived.
    pub(super) static LATE_EVICTED: AtomicU64 = AtomicU64::new(0);
    /// Whether a decryptor was ever installed in this process.
    ///
    /// The distinction that keeps every zero above honest. "No keys were
    /// supplied" and "keys were supplied and opened nothing" are opposite
    /// findings with opposite remedies, and both render as
    /// `decrypted_records: 0`.
    pub(super) static DECRYPTOR_INSTALLED: AtomicU64 = AtomicU64::new(0);
}

/// Record that a decryptor exists in this process.
///
/// Called when one is INSTALLED rather than when one is constructed: a
/// decryptor built to probe an embedded DSB block and then dropped because it
/// found no secrets never decrypted anything, and reporting it as installed
/// would turn "no keys were supplied" into "keys were supplied and failed".
pub fn note_tls_decryptor_installed(keylog_entries: usize, sessions_with_keys: usize) {
    tls_tally::DECRYPTOR_INSTALLED.store(1, Ordering::Relaxed);
    tls_tally::KEYLOG_ENTRIES.store(keylog_entries as u64, Ordering::Relaxed);
    tls_tally::SESSIONS_WITH_KEYS.store(sessions_with_keys as u64, Ordering::Relaxed);
}

/// Record that one ApplicationData record was offered to a decryptor.
///
/// Published as it happens rather than summed at the end, and that is the whole
/// point of the change: the end-of-run report reaches the CLI's summary, while
/// a live capture serving REST or MCP never gets there. A server asked "is
/// decryption working?" mid-run needs the answer now.
pub fn note_tls_record_offered() {
    tls_tally::APP_DATA_RECORDS.fetch_add(1, Ordering::Relaxed);
}

/// Record that one ApplicationData record was opened.
pub fn note_tls_record_decrypted() {
    tls_tally::DECRYPTED_RECORDS.fetch_add(1, Ordering::Relaxed);
}

/// Record that one held record was opened once its key arrived.
pub fn note_tls_record_late_recovered() {
    tls_tally::LATE_RECOVERED.fetch_add(1, Ordering::Relaxed);
}

/// Record that one held record was dropped before any key arrived.
///
/// Kept apart from [`note_tls_record_late_recovered`] because without it "we
/// never had the keys" and "we had them and had already discarded the
/// ciphertext" are the same silence.
pub fn note_tls_record_late_evicted() {
    tls_tally::LATE_EVICTED.fetch_add(1, Ordering::Relaxed);
}

/// The published TLS decryption state, readable from anywhere.
///
/// `None` when no decryptor was ever installed, which is a different answer
/// from a report of zeroes and must not be flattened into one: nothing was
/// supplied to decrypt WITH, so nothing failed.
#[must_use]
pub fn published_tls_decrypt() -> Option<TlsDecryptReport> {
    if tls_tally::DECRYPTOR_INSTALLED.load(Ordering::Relaxed) == 0 {
        return None;
    }
    Some(TlsDecryptReport {
        keylog_entries: tls_tally::KEYLOG_ENTRIES.load(Ordering::Relaxed) as usize,
        sessions_with_keys: tls_tally::SESSIONS_WITH_KEYS.load(Ordering::Relaxed) as usize,
        app_data_records: tls_tally::APP_DATA_RECORDS.load(Ordering::Relaxed),
        decrypted_records: tls_tally::DECRYPTED_RECORDS.load(Ordering::Relaxed),
        late_recovered: tls_tally::LATE_RECOVERED.load(Ordering::Relaxed),
        late_evicted: tls_tally::LATE_EVICTED.load(Ordering::Relaxed),
        // Never published: `late_still_held` is a point-in-time queue depth
        // rather than a monotonic count, and there is no note_* for it because
        // a running total of a queue describes no moment that ever existed.
        // Zero is the honest value for a reader outside the run.
        late_still_held: 0,
    })
}

/// What this run could not decode at all.
///
/// The counts sipnab prints describe what it understood. This describes what
/// reached it and produced nothing — the difference between "there is no SIP
/// here" and "I could not read one single frame of this", which the output
/// otherwise renders identically. Report it beside any packet count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndecodableReport {
    /// Total frames that produced no parsed packet. Exact: counted apart from
    /// the per-reason tables so a table that overflowed cannot understate it.
    pub frames: u64,
    /// Per-reason breakdown, most frames first, ties by label so the report
    /// is deterministic.
    pub reasons: Vec<UndecodableTally>,
    /// Frames counted in `frames` whose specific number is NOT in `reasons`,
    /// because the capture carried more distinct numbers than
    /// [`UNDECODABLE_REASON_SLOTS`]. Reported rather than hidden: a breakdown
    /// that quietly failed to add up to the total would be the same class of
    /// confident-wrong-answer this whole tally exists to remove.
    pub reasons_dropped: u64,
}

impl UndecodableReport {
    /// The per-reason breakdown as one comma-separated line, most frames
    /// first: `"linktype 143 (49), ethertype 0x88a8 (3)"`.
    ///
    /// A method rather than a helper beside each caller, because three
    /// surfaces render this list — the batch NOT DECODED notice, the no-SIP
    /// guidance, and the `--analyze` finding — and three copies of the same
    /// `join` is three chances for them to describe one capture differently.
    #[must_use]
    pub fn reason_list(&self) -> String {
        self.reasons
            .iter()
            .map(|t| format!("{} ({})", t.reason, t.frames))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Frames this run could not decode, as one number.
///
/// The cheap read for a `/metrics` scrape: a single relaxed load, where
/// [`undecodable_report`] walks the reason tables.
///
/// # Returns
///
/// Monotonic count of frames that reached the parser and produced no parsed
/// packet, since the process started or the last [`reset_undecodable_frames`].
#[must_use]
pub fn undecodable_frames() -> u64 {
    UNDECODABLE_FRAMES.load(Ordering::Relaxed)
}

/// Frames a snaplen cut short before sipnab saw them (`caplen < origlen`).
///
/// # Returns
///
/// Monotonic count since the process started or the last
/// [`reset_undecodable_frames`].
#[must_use]
pub fn snapped_frames() -> u64 {
    SNAPPED_FRAMES.load(Ordering::Relaxed)
}

/// Record that one frame arrived cut short by the capture's snaplen.
///
/// The compare is on the caller's hot path, so this is written as a branch the
/// common case does not pay for: an unsnapped capture performs one integer
/// comparison per frame and never touches the atomic. Only a capture that IS
/// being truncated pays the increment, and on that capture the information is
/// worth more than the relaxed add costs.
pub fn note_snapped_frame() {
    SNAPPED_FRAMES.fetch_add(1, Ordering::Relaxed);
}

/// The full undecodable breakdown for this run.
///
/// # Returns
///
/// An [`UndecodableReport`]; all zeroes and an empty breakdown when every
/// frame decoded.
#[must_use]
pub fn undecodable_report() -> UndecodableReport {
    let mut reasons = Vec::new();
    let mut dropped = 0u64;
    dropped += UNSUPPORTED_LINK_TYPE.collect(
        |k| UndecodableReason::UnsupportedLinkType(k as i32),
        &mut reasons,
    );
    dropped += NOT_IP.collect(
        |k| {
            UndecodableReason::NotIp(if k == TALLY_NO_NUMBER {
                None
            } else {
                Some(k as u16)
            })
        },
        &mut reasons,
    );
    dropped += NO_TRANSPORT.collect(
        |k| {
            UndecodableReason::NoTransport(if k == TALLY_NO_NUMBER {
                None
            } else {
                Some(k as u8)
            })
        },
        &mut reasons,
    );
    for (count, reason) in [
        (&TRUNCATED_FRAMES, UndecodableReason::Truncated),
        (&DECODE_ERRORS, UndecodableReason::DecodeError),
    ] {
        let frames = count.load(Ordering::Relaxed);
        if frames > 0 {
            reasons.push(UndecodableTally { reason, frames });
        }
    }
    // Busiest first; ties by label so two runs over the same capture print the
    // same order.
    reasons.sort_unstable_by(|a, b| {
        b.frames
            .cmp(&a.frames)
            .then_with(|| a.reason.label().cmp(&b.reason.label()))
    });
    UndecodableReport {
        frames: UNDECODABLE_FRAMES.load(Ordering::Relaxed),
        reasons,
        reasons_dropped: dropped,
    }
}

/// Clear the undecodable tally.
///
/// The counters are process-global, so a process that analyzes several
/// captures in sequence (and a test that asserts on exact counts) needs a way
/// back to zero — the same reason [`crate::pipeline::reset_portrange_skips`]
/// exists.
///
/// # Side effects
///
/// Zeroes the total, both scalar reasons, and every slot of the three keyed
/// tables.
pub fn reset_undecodable_frames() {
    UNDECODABLE_FRAMES.store(0, Ordering::Relaxed);
    SNAPPED_FRAMES.store(0, Ordering::Relaxed);
    TRUNCATED_FRAMES.store(0, Ordering::Relaxed);
    DECODE_ERRORS.store(0, Ordering::Relaxed);
    UNSUPPORTED_LINK_TYPE.reset();
    NOT_IP.reset();
    NO_TRANSPORT.reset();
}

/// The numbers the decoder had in hand when it gave up on a frame.
///
/// **Never re-derived from the frame's bytes.** `parse.rs` owns the one copy
/// of the link-layer walk on purpose — its own comment says "two would be two
/// places for an encapsulated packet's start offset to drift" — and a second
/// walk here would drift from it exactly on the encapsulations this feature
/// exists to explain, reporting a wrong EtherType with full confidence. So the
/// number travels OUT of the failure with the error rather than being
/// recovered from the bytes afterwards.
///
/// A field left `None` means "the decoder did not hand this number out", and
/// the reason then renders as *not recorded*. That is a true statement an
/// operator can act on ("sipnab could not read this frame, and cannot yet tell
/// you which EtherType"); a number produced by a stale second walk would not
/// be.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameFacts {
    /// EtherType the link layer named for the payload, when the decoder
    /// reached it.
    pub ethertype: Option<u16>,
    /// Protocol number of the innermost IP header the decoder reached.
    pub ip_protocol: Option<u8>,
}

impl FrameFacts {
    /// Nothing was handed out: every reason that needs a number renders as
    /// *not recorded*.
    pub const UNRECORDED: Self = Self {
        ethertype: None,
        ip_protocol: None,
    };
}

/// Why this error means the frame produced nothing, or `None` when the frame
/// was in fact understood.
///
/// The only `None` is [`CaptureError::Icmp`]: `parse_packet` has already
/// recorded that frame's quote as dialog evidence by the time it returns the
/// error, so the frame was read — it simply is not a `ParsedPacket`.
///
/// Matched exhaustively on purpose. A variant added later must be classified
/// deliberately, not swept into "decode error" by a wildcard.
///
/// # Arguments
///
/// * `err` — what the decoder said.
/// * `facts` — the numbers the decoder had in hand. Pure input: this function
///   never looks at frame bytes.
fn classify_undecodable(err: &CaptureError, facts: FrameFacts) -> Option<UndecodableReason> {
    Some(match err {
        CaptureError::UnsupportedLinkType(dlt) => UndecodableReason::UnsupportedLinkType(*dlt),
        // `NoIpPayload` joins `NotIp` rather than `Truncated`: an "IP layer
        // with no payload to walk into" is what a well-formed ARP frame
        // produces (etherparse slices it into `NetSlice::Arp`, which has no
        // IP payload), and ARP is the single commonest non-IP frame on any
        // Ethernet capture. Filing it as truncation would send an operator
        // to raise a snaplen that was never the problem. Genuine truncation
        // states its `need`/`got` and arrives as `TooShort`.
        CaptureError::NotIp { .. } | CaptureError::NoIpPayload { .. } => {
            UndecodableReason::NotIp(facts.ethertype)
        }
        // A GRE inner protocol IS an EtherType, and the error carries it, so
        // this reason is fully named without any help from `facts`.
        CaptureError::UnsupportedGreProtocol(p) => UndecodableReason::NotIp(Some(*p)),
        CaptureError::NoTransport => UndecodableReason::NoTransport(facts.ip_protocol),
        // The pre-parsed (HEP) path states the protocol in the error itself.
        CaptureError::UnsupportedIpProtocol(p) => UndecodableReason::NoTransport(Some(*p)),
        CaptureError::TooShort { .. } => UndecodableReason::Truncated,
        CaptureError::PacketDecode { .. } | CaptureError::EncapTooDeep { .. } => {
            UndecodableReason::DecodeError
        }
        CaptureError::Icmp => return None,
        // File-format errors are raised by the reader before any frame exists,
        // so they do not reach this site today. Classified rather than ignored
        // so that if one ever does it is counted instead of vanishing.
        CaptureError::NetMonFormat
        | CaptureError::UnknownFormat { .. }
        | CaptureError::GzipData
        | CaptureError::GzipDecode { .. }
        | CaptureError::GzipTooLarge { .. } => UndecodableReason::DecodeError,
    })
}

/// Count one frame the parser could not turn into a [`ParsedPacket`].
///
/// # Arguments
///
/// * `err` — what the parser said.
/// * `facts` — the numbers the parser had in hand; [`FrameFacts::UNRECORDED`]
///   when it handed none out.
///
/// # Side effects
///
/// Bumps the process-global total and the tally for the classified reason. No
/// allocation and no lock: this runs once per undecodable frame, which on a
/// capture sipnab cannot read is once per frame.
pub fn record_undecodable(err: &CaptureError, facts: FrameFacts) {
    let Some(reason) = classify_undecodable(err, facts) else {
        return;
    };
    UNDECODABLE_FRAMES.fetch_add(1, Ordering::Relaxed);
    match reason {
        UndecodableReason::UnsupportedLinkType(dlt) => {
            UNSUPPORTED_LINK_TYPE.bump(i64::from(dlt));
        }
        UndecodableReason::NotIp(et) => {
            NOT_IP.bump(et.map_or(TALLY_NO_NUMBER, i64::from));
        }
        UndecodableReason::NoTransport(p) => {
            NO_TRANSPORT.bump(p.map_or(TALLY_NO_NUMBER, i64::from));
        }
        UndecodableReason::Truncated => {
            TRUNCATED_FRAMES.fetch_add(1, Ordering::Relaxed);
        }
        UndecodableReason::DecodeError => {
            DECODE_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Output of [`PacketProcessor::process`]: the parsed packets ready from one
/// input packet. Inline-sized for one element — the dominant case (UDP, a
/// single-frame TCP message, one reassembled fragment) allocates nothing;
/// only a multi-message TCP segment spills to the heap.
pub type ParsedPackets = SmallVec<[ParsedPacket; 1]>;
#[cfg(feature = "native")]
pub use writer::{PcapExportMode, PcapWriter};

use parse::parse_packet;
use reassembly::{FragmentReassembler, TcpReassembler};

/// Stateful packet processing pipeline.
///
/// Combines header parsing, IP fragment reassembly, and TCP segment
/// reassembly into a single processing step. Feed raw [`Packet`]s in and
/// get back zero or more [`ParsedPacket`]s ready for upper-layer parsing.
pub struct PacketProcessor {
    /// IPv4/IPv6 fragment reassembler (bounded, oldest-out eviction).
    fragment_reassembler: FragmentReassembler,
    /// TCP stream reassembler that reorders segments before SIP framing.
    tcp_reassembler: TcpReassembler,
    /// Per-direction leftover bytes of an incomplete trailing SIP message held
    /// across TCP flushes (SNB-0008). Keyed by (src, dst); bounded by
    /// `max_sessions`. Map order is update recency (every touch `shift_remove`s
    /// and re-inserts), so index 0 is always the least-recently-updated entry.
    tcp_sip_leftover: indexmap::IndexMap<
        (std::net::SocketAddr, std::net::SocketAddr),
        Vec<u8>,
        ahash::RandomState,
    >,
    /// Cap on tracked `tcp_sip_leftover` sessions; when full, the
    /// least-recently-updated entry is evicted to keep memory bounded.
    max_sessions: usize,
    /// Cross-packet SCTP DATA fragment reassembler (RFC 4960 §3.3.1): buffers a
    /// SIP message split across B/middle/E DATA chunks until the E fragment
    /// arrives. Bounded, least-recently-updated eviction.
    sctp_reassembler: parse::SctpReassembler,
    /// When `false` (`--no-reassembly`), IP fragments and TCP segments pass
    /// through as individual packets instead of being reassembled/reframed.
    reassembly: bool,
    /// When `Some(n)` (`-S`/`--limitlen`), each emitted packet's payload is
    /// truncated to `n` bytes before upper-layer parsing — the sipgrep `-S`
    /// "look at only the first N bytes" cap, independent of the capture snaplen.
    parse_limit: Option<usize>,
}

/// Default reassembly session cap (matches the reassemblers' default).
const DEFAULT_MAX_SESSIONS: usize = 10_000;

/// Upper bound on a single held partial SIP message (bytes). A larger remainder
/// is flushed rather than buffered, so a peer can't pin memory with an
/// unterminated message.
///
/// DERIVED from the reassembly ceiling rather than stated beside it. The two
/// used to be separate spellings of 65 536 that happened to agree, and they
/// bound the same message from opposite ends: a peer that sends its large
/// message with `PSH` on every segment never fills the reassembler's buffer at
/// all — each push flushes — so the partial is held HERE while the rest
/// arrives. Raising only the reassembly ceiling would leave that message
/// chopped at 64 KiB anyway, which from the outside looks exactly like a
/// setting that does nothing.
fn max_tcp_leftover() -> usize {
    reassembly::max_tcp_buffer()
}

impl PacketProcessor {
    /// Create a new packet processor with default reassembly limits.
    pub fn new() -> Self {
        Self {
            fragment_reassembler: FragmentReassembler::new(),
            tcp_reassembler: TcpReassembler::new(),
            tcp_sip_leftover: indexmap::IndexMap::default(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            sctp_reassembler: parse::SctpReassembler::new(),
            reassembly: true,
            parse_limit: None,
        }
    }

    /// Builder: enable or disable IP-fragment / TCP-segment reassembly
    /// (`--no-reassembly` sets this `false`). Default `true`.
    #[must_use]
    pub fn with_reassembly(mut self, on: bool) -> Self {
        self.reassembly = on;
        self
    }

    /// Builder: cap the bytes of each emitted packet handed to the parser
    /// (`-S`/`--limitlen`). Default `None` (no cap).
    #[must_use]
    pub fn with_parse_limit(mut self, limit: Option<usize>) -> Self {
        self.parse_limit = limit;
        self
    }

    /// Create a new packet processor with a custom maximum reassembly session count.
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self {
            fragment_reassembler: FragmentReassembler::with_limits(
                max_sessions,
                reassembly::reassembly_ttl(),
            ),
            tcp_reassembler: TcpReassembler::with_limits(
                max_sessions,
                reassembly::reassembly_ttl(),
            ),
            tcp_sip_leftover: indexmap::IndexMap::default(),
            max_sessions,
            sctp_reassembler: parse::SctpReassembler::with_max_streams(max_sessions),
            reassembly: true,
            parse_limit: None,
        }
    }

    /// Process a raw captured packet through the parsing and reassembly pipeline.
    ///
    /// Returns zero or more [`ParsedPacket`]s:
    /// - **Zero:** packet is non-IP, a buffered fragment, or a buffered TCP segment.
    /// - **One:** typical UDP packet or a completed fragment/TCP flush.
    /// - **Multiple:** TCP reassembly may flush several accumulated segments.
    ///
    /// Applies the `-S`/`--limitlen` parse cap to every emitted packet.
    ///
    /// # Arguments
    ///
    /// * `packet` - the raw captured packet (link-layer frame plus metadata).
    ///
    /// # Side effects
    ///
    /// Mutates the fragment/TCP reassembler state and the held-partial map
    /// via `process_inner`, and bumps the process-wide captured-packet
    /// counter read by [`captured_packets`] (and so by every `/metrics`
    /// scrape). Counted before parsing: an unparseable frame was still
    /// captured.
    pub fn process(&mut self, packet: &Packet) -> ParsedPackets {
        CAPTURED_PACKETS.fetch_add(1, Ordering::Relaxed);
        let mut out = self.process_inner(packet);
        if let Some(limit) = self.parse_limit {
            for p in out.iter_mut() {
                if p.payload.len() > limit {
                    p.payload = p.payload.slice(..limit);
                }
            }
        }
        out
    }

    /// Core dispatch behind `process`: parse the packet, then route it through
    /// IP-fragment reassembly, TCP reassembly plus SIP framing, or (for UDP and
    /// other transports) pass it through directly.
    ///
    /// # Arguments
    ///
    /// * `packet` - the raw captured packet to parse and reassemble.
    ///
    /// # Returns
    ///
    /// Zero or more parsed packets, before the `-S`/`--limitlen` cap is
    /// applied (that happens in `process`). Empty when the packet is
    /// unparseable, a buffered IP fragment, or a buffered TCP segment.
    ///
    /// # Side effects
    ///
    /// Mutates both reassemblers and the `tcp_sip_leftover` map (inserting,
    /// removing, and — at the `max_sessions` cap — evicting the
    /// least-recently-updated held partial); counts every unparseable frame
    /// into the process-global tally read by [`undecodable_report`], and logs
    /// it at debug level.
    fn process_inner(&mut self, packet: &Packet) -> ParsedPackets {
        let parsed = match parse_packet(packet) {
            Ok(p) => p,
            Err(e) => {
                // The one place a frame can vanish. Counted before the log,
                // because `debug!` is off by default and used to be the only
                // trace a frame left — which is how a capture sipnab decoded
                // 0% of reported the same totals as a clean read.
                //
                // `UNRECORDED`: `parse_packet` does not yet hand its
                // link-layer EtherType or innermost IP protocol back to its
                // caller, so those two reasons render as *not recorded* until
                // it does. Re-walking `packet` here to recover them is the one
                // thing this must not do — see [`FrameFacts`].
                record_undecodable(&e, FrameFacts::UNRECORDED);
                tracing::debug!("Skipping unparseable packet: {e}");
                return SmallVec::new();
            }
        };

        // Reassembly disabled (`--no-reassembly`): every packet stands alone —
        // IP fragments and TCP segments are neither reassembled nor reframed.
        if !self.reassembly {
            return smallvec![parsed];
        }

        // A uprobe read is a complete application write, not a segment of a
        // byte stream. It is reported as TCP because that is what the TLS
        // session runs over, but it never traversed a sequence space: it was
        // taken where the application handed the bytes to its TLS library, in
        // one call, with the message boundary the application chose.
        //
        // Feeding it to the TCP reassembler is what silence looked like before
        // this: the reassembler orders segments by sequence number, a uprobe
        // packet carries `tcp_seq: None`, and every message was held for
        // neighbors that would never arrive. Both uprobe backends captured
        // packets and produced zero SIP messages.
        if parsed.input_origin == parse::InputOrigin::Uprobe {
            return smallvec![parsed];
        }

        // Check if this is an IP fragment that needs reassembly
        let is_fragment =
            parsed.fragment_offset.is_some_and(|off| off > 0) || parsed.more_fragments;

        if is_fragment {
            return match self.fragment_reassembler.insert(&parsed) {
                Some(reassembled) => {
                    // The reassembled buffer is the full IP payload (transport
                    // header + data). Re-parse the transport header so the ports
                    // and offset are recovered — the fragments themselves carried
                    // no usable transport header, so without this the payload
                    // still begins with the UDP/TCP header and SIP parsing fails.
                    let mut completed = parsed;
                    if let Some((sp, dp, tp, hdr)) =
                        parse::reparse_transport(completed.ip_protocol, &reassembled)
                    {
                        completed.src_port = sp;
                        completed.dst_port = dp;
                        completed.transport = tp;
                        completed.payload = bytes::Bytes::copy_from_slice(&reassembled[hdr..]);
                        if tp == parse::TransportProto::Tcp {
                            // The reassembled datagram is one TCP segment of an
                            // ongoing stream, not a complete unit: recover its
                            // seq/flags (reparse validated >= 20 header bytes)
                            // and feed it through the TCP reassembler + SIP
                            // framer so a message spanning this segment and
                            // its neighbors still completes.
                            completed.tcp_seq = Some(u32::from_be_bytes([
                                reassembled[4],
                                reassembled[5],
                                reassembled[6],
                                reassembled[7],
                            ]));
                            let f = reassembled[13];
                            completed.tcp_flags = Some(parse::TcpFlags {
                                syn: f & 0x02 != 0,
                                ack: f & 0x10 != 0,
                                fin: f & 0x01 != 0,
                                rst: f & 0x04 != 0,
                                psh: f & 0x08 != 0,
                            });
                            completed.fragment_offset = Some(0);
                            completed.more_fragments = false;
                            return self.process_tcp(&completed);
                        }
                    } else {
                        completed.payload = reassembled.into();
                    }
                    completed.fragment_offset = Some(0);
                    completed.more_fragments = false;
                    smallvec![completed]
                }
                None => SmallVec::new(),
            };
        }

        // TCP: feed into reassembler, then frame the reassembled byte stream
        // into individual SIP messages (SNB-0008 — one segment can carry many).
        if parsed.transport == parse::TransportProto::Tcp {
            return self.process_tcp(&parsed);
        }

        // SCTP: `parse_packet` already emits the SIP payload of a single-packet
        // complete (B+E) DATA chunk. An empty SCTP payload may instead be a DATA
        // fragment of a message split across packets (RFC 4960 §3.3.1) — recover
        // the fragment and feed it to the reassembler; the whole message emerges
        // on the E fragment. Non-DATA / malformed SCTP falls through unchanged.
        if parsed.transport == parse::TransportProto::Sctp
            && parsed.payload.is_empty()
            && let Some(frag) = parse::parse_sctp_fragment(packet)
        {
            let src = std::net::SocketAddr::new(parsed.src_addr, frag.src_port);
            let dst = std::net::SocketAddr::new(parsed.dst_addr, frag.dst_port);
            return match self.sctp_reassembler.insert(src, dst, &frag) {
                Some(payload) => {
                    let mut completed = parsed;
                    completed.src_port = frag.src_port;
                    completed.dst_port = frag.dst_port;
                    completed.payload = payload;
                    smallvec![completed]
                }
                // A buffered fragment (or a fail-closed drop) emits nothing yet.
                None => SmallVec::new(),
            };
        }

        // UDP (and other non-TCP, non-fragment): ready immediately
        smallvec![parsed]
    }

    /// TCP arm of `process_inner`: feed the segment (fresh from capture or an
    /// IP-reassembled datagram with recovered seq/flags) into the TCP
    /// reassembler, then frame the flushed byte stream into individual SIP
    /// messages, holding/prepending per-direction partials (SNB-0008).
    fn process_tcp(&mut self, parsed: &ParsedPacket) -> ParsedPackets {
        let flushed = self.tcp_reassembler.insert(parsed);
        let src = std::net::SocketAddr::new(parsed.src_addr, parsed.src_port);
        let dst = std::net::SocketAddr::new(parsed.dst_addr, parsed.dst_port);
        let key = (src, dst);
        // `false` here means the connection ended on this packet (FIN/RST):
        // a held partial will never complete, so flush it as a truncated tail.
        let stream_open = self.tcp_reassembler.contains(src, dst);

        if flushed.is_empty() {
            // Connection ended (FIN/RST) with a partial message still held:
            // surface it as a truncated tail so it is flagged malformed
            // downstream rather than silently dropped.
            if !stream_open
                && let Some(rem) = self.tcp_sip_leftover.shift_remove(&key)
                && !rem.is_empty()
            {
                let mut p = parsed.clone();
                p.payload = bytes::Bytes::from(rem);
                return smallvec![p];
            }
            return SmallVec::new();
        }

        // Prepend any partial message held from a previous flush.
        let mut buf = self.tcp_sip_leftover.shift_remove(&key).unwrap_or_default();
        for chunk in &flushed {
            buf.extend_from_slice(chunk);
        }

        // Only SIP-over-TCP is Content-Length framed. TLS, WebSocket, and any
        // other binary TCP payload must pass through whole (downstream
        // try_tls_decrypt / websocket unwrap handle them) — framing them as
        // SIP would swallow them.
        if !crate::sip::is_sip_message(&buf) {
            let mut p = parsed.clone();
            p.payload = bytes::Bytes::from(buf);
            return smallvec![p];
        }

        let (ranges, consumed) = frame_tcp_sip(&buf);

        // A held partial must be an owned, growable Vec (the next flush is
        // appended to it), so copy just the tail out — before `buf` is frozen
        // into `Bytes` below. This is the same single tail copy as before.
        let held_tail =
            (consumed < buf.len() && stream_open && buf.len() - consumed <= max_tcp_leftover())
                .then(|| buf[consumed..].to_vec());

        // Freeze the stream buffer once: every framed message (and an
        // end-of-stream tail) becomes a zero-copy view into this single
        // allocation, instead of one fresh copy per message. The payloads
        // share the allocation, which stays alive until the last downstream
        // consumer drops its packet — the framed ranges cover (nearly) all
        // of it, so nothing meaningful is pinned beyond its use.
        let total = buf.len();
        let frozen = bytes::Bytes::from(buf);

        let mut out: ParsedPackets = ranges
            .into_iter()
            .map(|r| {
                let mut p = parsed.clone();
                p.payload = frozen.slice(r);
                p
            })
            .collect();

        if let Some(tail) = held_tail {
            // More bytes may arrive — hold the partial for the next flush.
            if !self.tcp_sip_leftover.contains_key(&key)
                && self.tcp_sip_leftover.len() >= self.max_sessions
            {
                // Index 0 is the least-recently-updated held partial
                // (map order is update recency), so the stalest entry
                // goes — never an active session's partial data.
                self.tcp_sip_leftover.shift_remove_index(0);
            }
            self.tcp_sip_leftover.insert(key, tail);
        } else if consumed < total {
            // Connection ended (or the partial is oversized): surface the
            // truncated tail so a downstream parser can flag it malformed
            // rather than silently dropping it.
            let mut p = parsed.clone();
            p.payload = frozen.slice(consumed..);
            out.push(p);
        }
        out
    }

    /// Sweep stale entries from both reassemblers.
    ///
    /// Should be called periodically (e.g., every 5 seconds) to evict
    /// incomplete fragments and idle TCP streams.
    ///
    /// # Side effects
    ///
    /// Removes timed-out entries from both reassemblers and drops any held
    /// SIP partial whose TCP stream is no longer tracked.
    pub fn sweep(&mut self) {
        self.fragment_reassembler.sweep();
        self.tcp_reassembler.sweep();
        // Drop held SIP partials whose TCP stream was swept (timed out without a
        // FIN), so an idle half-message can't leak.
        self.tcp_sip_leftover
            .retain(|(src, dst), _| self.tcp_reassembler.contains(*src, *dst));
    }
}

impl Default for PacketProcessor {
    /// Equivalent to `PacketProcessor::new()` (default limits, reassembly on).
    fn default() -> Self {
        Self::new()
    }
}

/// Frame a reassembled TCP byte stream into individual SIP messages.
///
/// Over TCP, SIP message boundaries are delimited by `Content-Length`, not by
/// packet boundaries — a single TCP segment can carry several complete messages
/// (and a flush can end mid-message). This walks `data` message by message:
/// for each, it finds the end of headers (`\r\n\r\n`, or `\n\n`), reads
/// `Content-Length` (absent ⇒ 0; compact form `l` honored), and the message
/// spans up to `header_end + content_length`. The body is taken verbatim by
/// length, so a blank line *inside* a body never splits a message.
///
/// Returns the byte ranges of the complete messages plus `consumed` — the index
/// where the first incomplete (held-back) message begins. `data[consumed..]`
/// should be retained and prepended to the next flush of the same stream.
pub(crate) fn frame_tcp_sip(data: &[u8]) -> (Vec<std::ops::Range<usize>>, usize) {
    let mut ranges = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let rest = &data[pos..];
        let Some(body_start) = find_header_end(rest) else {
            break; // headers not yet complete — hold the remainder
        };
        let content_length = parse_content_length(&rest[..body_start]);
        let msg_end = match body_start.checked_add(content_length) {
            Some(e) => e,
            None => break, // absurd Content-Length overflow — hold
        };
        if rest.len() < msg_end {
            break; // body not fully arrived — hold the remainder
        }
        ranges.push(pos..pos + msg_end);
        pos += msg_end;
    }
    (ranges, pos)
}

/// Find the end of the SIP header section, returning the index just past the
/// blank-line separator (i.e. where the body starts). Accepts CRLFCRLF and the
/// lenient LFLF form. `None` if no complete header terminator is present yet.
fn find_header_end(data: &[u8]) -> Option<usize> {
    // SIMD substring search (memchr) rather than scalar `windows()` scans —
    // this runs once per candidate message on the TCP framing path. Both
    // forms are searched and the earliest wins; `\r\n\r\n` cannot contain
    // `\n\n` (the `\r` separates the newlines), so the two never overlap.
    let crlf = memchr::memmem::find(data, b"\r\n\r\n").map(|i| i + 4);
    let lf = memchr::memmem::find(data, b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Parse `Content-Length` (or its compact form `l`) from a SIP header block.
/// Returns 0 when absent or unparseable (the framer then treats the message as
/// bodyless; a downstream parser still flags any real mismatch).
fn parse_content_length(headers: &[u8]) -> usize {
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = std::str::from_utf8(&line[..colon]).unwrap_or("").trim();
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("l") {
            let val = std::str::from_utf8(&line[colon + 1..]).unwrap_or("").trim();
            return val.parse::<usize>().unwrap_or(0);
        }
    }
    0
}

/// Parse a duration string like "30s", "5m", "1h" into a [`Duration`].
///
/// Supported suffixes: `s` (seconds), `m` (minutes), `h` (hours).
/// A bare number is treated as seconds.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Empty duration string");
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else {
        (s, 1u64) // Bare number = seconds
    };

    let value: u64 = num_str
        .parse()
        .with_context(|| format!("Invalid duration value: '{num_str}'"))?;

    Ok(Duration::from_secs(value * multiplier))
}

/// Unit tests for duration parsing, TCP SIP framing, and the
/// `PacketProcessor` pipeline (fragment/TCP reassembly dispatch).
#[cfg(test)]
mod tests {
    use super::*;

    /// "30s" and a bare "30" both parse as 30 seconds.
    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
    }

    /// "5m" parses as 300 seconds.
    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    /// "2h" parses as 7200 seconds.
    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    /// Empty strings, non-numeric values, and unknown suffixes are errors.
    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5x").is_err());
    }

    // ── TCP SIP framing (SNB-0008) ──────────────────────────────────
    // Over TCP one segment may carry several SIP messages; the framer must
    // split them all (not just the first), hold an incomplete tail, and never
    // split on a blank line inside a body.

    /// Build a complete bodyless OPTIONS message whose Via branch and Call-ID
    /// are `cid`, as raw bytes.
    fn opts(cid: &str) -> Vec<u8> {
        format!(
            "OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/TCP h;branch={cid}\r\n\
             Call-ID: {cid}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    /// Run `frame_tcp_sip` over `data` and return the framed messages as
    /// lossy strings plus the consumed byte count.
    fn frame_strs(data: &[u8]) -> (Vec<String>, usize) {
        let (ranges, consumed) = frame_tcp_sip(data);
        (
            ranges
                .iter()
                .map(|r| String::from_utf8_lossy(&data[r.clone()]).into_owned())
                .collect(),
            consumed,
        )
    }

    /// Three complete messages in one buffer are all framed, in order, with
    /// the whole buffer consumed.
    #[test]
    fn frame_three_complete_messages_in_one_buffer() {
        let mut buf = opts("a");
        buf.extend(opts("b"));
        buf.extend(opts("c"));
        let total = buf.len();
        let (msgs, consumed) = frame_strs(&buf);
        assert_eq!(msgs.len(), 3, "all three messages must be framed");
        assert!(msgs[0].contains("Call-ID: a"));
        assert!(msgs[1].contains("Call-ID: b"));
        assert!(msgs[2].contains("Call-ID: c"));
        assert_eq!(consumed, total, "fully consumed, nothing held");
    }

    /// A trailing message whose headers lack the blank-line terminator is
    /// held (not framed); `consumed` stops at its start.
    #[test]
    fn frame_holds_incomplete_trailing_headers() {
        let mut buf = opts("a");
        buf.extend(opts("b"));
        let consumed_expected = buf.len();
        buf.extend_from_slice(b"OPTIONS sip:h SIP/2.0\r\nCall-ID: partial\r\n"); // no \r\n\r\n
        let (msgs, consumed) = frame_strs(&buf);
        assert_eq!(msgs.len(), 2, "two complete; the partial third is held");
        assert_eq!(consumed, consumed_expected, "held bytes start after msg 2");
    }

    /// A message with complete headers but fewer body bytes than
    /// Content-Length declares is held until the body arrives.
    #[test]
    fn frame_holds_message_with_unfinished_body() {
        // Headers complete, Content-Length declares 10 but no body bytes yet.
        let mut buf = opts("a");
        let after_a = buf.len();
        buf.extend_from_slice(b"INVITE sip:h SIP/2.0\r\nCall-ID: b\r\nContent-Length: 10\r\n\r\n");
        let (msgs, consumed) = frame_strs(&buf);
        assert_eq!(msgs.len(), 1, "only the bodyless OPTIONS is complete");
        assert_eq!(
            consumed, after_a,
            "the CL:10 message is held until its body"
        );
    }

    /// A body containing its own blank line is taken whole by Content-Length,
    /// never split at the embedded separator.
    #[test]
    fn frame_body_with_embedded_blank_line_not_split() {
        // A body that itself contains \r\n\r\n must be taken by Content-Length,
        // not split at the blank line.
        let body = "v=0\r\n\r\no=x"; // 10 bytes, contains a blank line
        let msg = format!(
            "INVITE sip:h SIP/2.0\r\nCall-ID: b\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let mut buf = msg.clone();
        buf.extend(opts("tail"));
        let (msgs, consumed) = frame_strs(&buf);
        assert_eq!(
            msgs.len(),
            2,
            "the INVITE (with blank-line body) + the OPTIONS"
        );
        assert!(
            msgs[0].ends_with("o=x"),
            "body taken whole by Content-Length"
        );
        assert_eq!(consumed, buf.len());
    }

    /// The compact `l:` form of Content-Length is honored when framing.
    #[test]
    fn frame_compact_content_length_header() {
        let body = "abcd";
        let msg = format!("MESSAGE sip:h SIP/2.0\r\nCall-ID: m\r\nl: 4\r\n\r\n{body}").into_bytes();
        let (msgs, consumed) = frame_strs(&msg);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].ends_with("abcd"), "compact 'l' header honored");
        assert_eq!(consumed, msg.len());
    }

    /// A message using bare-LF line endings (LFLF header terminator) frames.
    #[test]
    fn frame_lenient_lf_only_separator() {
        let msg = b"OPTIONS sip:h SIP/2.0\nCall-ID: x\nContent-Length: 0\n\n";
        let (msgs, consumed) = frame_strs(msg);
        assert_eq!(msgs.len(), 1, "LFLF terminator accepted");
        assert_eq!(consumed, msg.len());
    }

    /// The earliest of CRLFCRLF/LFLF wins and the index lands just past it.
    #[test]
    fn find_header_end_takes_earliest_terminator() {
        // Pins the CRLFCRLF-vs-LFLF precedence: the earliest blank-line
        // separator of either form wins, and the index is just past it.
        assert_eq!(find_header_end(b"A: b\r\n\r\nBODY"), Some(8));
        assert_eq!(find_header_end(b"A: b\n\nBODY"), Some(6));
        // A lenient LFLF before a later CRLFCRLF wins (earliest).
        assert_eq!(find_header_end(b"A\n\nx\r\n\r\ny"), Some(3));
        // A CRLFCRLF before a later LFLF wins.
        assert_eq!(find_header_end(b"A\r\n\r\nx\n\ny"), Some(5));
        // Incomplete: no terminator yet.
        assert_eq!(find_header_end(b"A: b\r\nCall-ID: x\r\n"), None);
    }

    /// Bodies with NULs, backslashes, and CRLFs are framed strictly by length.
    #[test]
    fn frame_adversarial_bodies() {
        // Body with backslashes, embedded NUL, and special chars — taken whole.
        let body = b"a\\b\x00c\r\nd";
        let mut msg = format!(
            "MESSAGE sip:h SIP/2.0\r\nCall-ID: z\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        msg.extend_from_slice(body);
        let after = msg.len();
        msg.extend(opts("next"));
        let (ranges, consumed) = frame_tcp_sip(&msg);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 0..after, "NUL/backslash body framed by length");
        assert_eq!(consumed, msg.len());
    }

    /// Empty input frames nothing; terminator-less garbage is held entirely.
    #[test]
    fn frame_empty_and_garbage() {
        // Empty input: nothing framed, nothing consumed.
        assert_eq!(frame_tcp_sip(b""), (vec![], 0));
        // Garbage without a header terminator: held entirely (consumed 0).
        let (ranges, consumed) = frame_tcp_sip(b"not a sip message at all");
        assert!(ranges.is_empty());
        assert_eq!(consumed, 0);
    }

    /// Build an EN10MB frame (Ethernet+IPv4+TCP) carrying `payload`, so a raw
    /// `Packet` can be pushed through `PacketProcessor::process` end to end.
    fn tcp_frame(payload: &[u8], seq: u32, psh: bool, fin: bool) -> Packet {
        tcp_frame_from(5230, payload, seq, psh, fin)
    }

    /// `tcp_frame` with a chosen source port, so tests can drive several
    /// distinct TCP connections through one processor.
    fn tcp_frame_from(src_port: u16, payload: &[u8], seq: u32, psh: bool, fin: bool) -> Packet {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&src_port.to_be_bytes());
        tcp.extend_from_slice(&[0x13, 0xc4]); // dst port 5060
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]); // ack
        let flags = 0x10 | if psh { 0x08 } else { 0 } | if fin { 0x01 } else { 0 };
        tcp.extend_from_slice(&[0x50, flags]); // data offset 5 words + flags
        tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]); // window, csum(0), urg
        tcp.extend_from_slice(payload);

        let total_len = (20 + tcp.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]); // id, flags, ttl, proto=6, csum0
        ip.extend_from_slice(&[127, 0, 0, 1]); // src
        ip.extend_from_slice(&[127, 0, 0, 2]); // dst
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]); // IPv4
        eth.extend_from_slice(&ip);

        let len = eth.len();
        Packet::new(
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            eth,
            len,
            len,
            None,
            1, // DLT_EN10MB
        )
    }

    /// SNB-0008 regression: three SIP messages packed into one TCP segment
    /// all emerge from `process`, not just the first.
    #[test]
    fn process_splits_multiple_sip_messages_in_one_tcp_segment() {
        // SNB-0008 regression: three SIP messages packed into one TCP segment
        // must all emerge from process(), not just the first.
        let mut payload = opts("a");
        payload.extend(opts("b"));
        payload.extend(opts("c"));
        let pkt = tcp_frame(&payload, 1000, true, false);

        let mut proc = PacketProcessor::new();
        let out = proc.process(&pkt);
        assert_eq!(out.len(), 3, "every message in the segment is emitted");
        let ids: Vec<String> = out
            .iter()
            .map(|p| String::from_utf8_lossy(&p.payload).into_owned())
            .collect();
        assert!(ids[0].contains("Call-ID: a"));
        assert!(ids[1].contains("Call-ID: b"));
        assert!(ids[2].contains("Call-ID: c"));
        assert!(
            out.iter()
                .all(|p| p.transport == parse::TransportProto::Tcp)
        );
    }

    /// TCP framing must be zero-copy: every message emitted from one segment
    /// is a view into one shared buffer, so consecutive payloads are exactly
    /// contiguous in memory. Per-message `copy_from_slice` would put each
    /// payload in its own heap allocation (never contiguous — allocator
    /// chunk headers/alignment sit between them).
    #[test]
    fn tcp_framing_emits_zero_copy_slices_of_one_buffer() {
        let mut payload = opts("a");
        payload.extend(opts("b"));
        payload.extend(opts("c"));
        let mut proc = PacketProcessor::new();
        let out = proc.process(&tcp_frame(&payload, 1000, true, false));
        assert_eq!(out.len(), 3);
        let p0 = out[0].payload.as_ptr() as usize;
        let p1 = out[1].payload.as_ptr() as usize;
        let p2 = out[2].payload.as_ptr() as usize;
        assert_eq!(
            p1,
            p0 + out[0].payload.len(),
            "second message must be a view directly after the first"
        );
        assert_eq!(
            p2,
            p1 + out[1].payload.len(),
            "third message must be a view directly after the second"
        );
    }

    /// A partial message held while the stream is open is emitted truncated
    /// on FIN so a downstream parser can flag it, never silently dropped.
    #[test]
    fn process_surfaces_truncated_tail_on_fin() {
        // A message whose body never completes before the connection closes is
        // held while the stream is open, then emitted (truncated) on FIN so a
        // downstream parser can flag it malformed — never silently dropped.
        let mut proc = PacketProcessor::new();
        let head = b"INVITE sip:h SIP/2.0\r\nCall-ID: trunc\r\nContent-Length: 60\r\n\r\n";
        let out1 = proc.process(&tcp_frame(head, 1, true, false));
        assert_eq!(
            out1.len(),
            0,
            "incomplete body held while the stream is open"
        );
        // FIN with no new data: the held partial must be surfaced.
        let out2 = proc.process(&tcp_frame(b"", 1 + head.len() as u32, false, true));
        assert_eq!(out2.len(), 1, "truncated tail emitted on FIN, not dropped");
        assert!(String::from_utf8_lossy(&out2[0].payload).contains("Call-ID: trunc"));
    }

    /// With `--no-reassembly` a multi-message TCP segment passes through as
    /// one raw packet, byte-for-byte, instead of being reframed.
    #[test]
    fn no_reassembly_passes_tcp_segment_through_unframed() {
        // Two SIP messages packed in one TCP segment: with reassembly OFF
        // (sipgrep -a inverse) the raw segment emerges as a single packet,
        // not reframed into individual messages.
        let mut payload = opts("a");
        payload.extend(opts("b"));
        let pkt = tcp_frame(&payload, 1000, true, false);

        let mut proc = PacketProcessor::new().with_reassembly(false);
        let out = proc.process(&pkt);
        assert_eq!(
            out.len(),
            1,
            "no reassembly emits the raw segment as one packet"
        );
        assert_eq!(
            &out[0].payload[..],
            &payload[..],
            "bytes pass through intact"
        );
    }

    /// The default processor (reassembly on) reframes the same two-message
    /// segment into two separate parsed packets.
    #[test]
    fn reassembly_on_by_default_reframes_tcp() {
        // Contrast: the default processor DOES reframe the same segment.
        let mut payload = opts("a");
        payload.extend(opts("b"));
        let mut proc = PacketProcessor::new();
        let out = proc.process(&tcp_frame(&payload, 1000, true, false));
        assert_eq!(
            out.len(),
            2,
            "default reassembly reframes into two messages"
        );
    }

    /// Binary TCP payloads (e.g. TLS records) are never SIP-framed, even when
    /// they contain a CRLFCRLF — they pass through whole for TLS decryption.
    #[test]
    fn process_passes_non_sip_tcp_through_unframed() {
        // TLS-over-TCP (and other binary payloads) must NOT be SIP-framed — they
        // pass through whole so downstream TLS decryption still sees them.
        let mut proc = PacketProcessor::new();
        // A TLS ClientHello-ish record: type 0x16, version 0x0301, then bytes
        // that happen to include a CRLFCRLF, to prove framing is not applied.
        let tls = b"\x16\x03\x01\x00\x20payload\r\n\r\nmore-tls-bytes-here";
        let out = proc.process(&tcp_frame(tls, 1, true, false));
        assert_eq!(
            out.len(),
            1,
            "non-SIP TCP payload emerges as a single packet"
        );
        assert_eq!(&out[0].payload[..], &tls[..], "bytes pass through intact");
    }

    /// A body split across two TCP segments is held silently, then emitted
    /// complete once the rest of the body arrives.
    #[test]
    fn process_holds_partial_across_segments_then_completes() {
        // A message body split across two TCP segments must be held, not
        // emitted as a (false) malformed message, then completed on arrival.
        let mut proc = PacketProcessor::new();
        let head = b"MESSAGE sip:h SIP/2.0\r\nCall-ID: split\r\nContent-Length: 5\r\n\r\nab";
        let out1 = proc.process(&tcp_frame(head, 1, true, false));
        assert_eq!(
            out1.len(),
            0,
            "incomplete body is held, nothing emitted yet"
        );
        let out2 = proc.process(&tcp_frame(b"cde", 1 + head.len() as u32, true, false));
        assert_eq!(
            out2.len(),
            1,
            "the completed message is emitted once the body arrives"
        );
        assert!(String::from_utf8_lossy(&out2[0].payload).ends_with("abcde"));
    }

    /// Split the same TCP segment `tcp_frame` would build into two IPv4
    /// fragments of one datagram (`ip_id`), cut `split` bytes into the IP
    /// payload (`split` must be a multiple of 8, past the 20-byte TCP
    /// header). Returns (first fragment MF=1, last fragment MF=0).
    fn tcp_fragment_frames(
        payload: &[u8],
        seq: u32,
        psh: bool,
        ip_id: u16,
        split: usize,
    ) -> (Packet, Packet) {
        assert_eq!(split % 8, 0, "IPv4 fragment offsets are 8-byte units");
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&[0x14, 0x6e]); // src port 5230
        tcp.extend_from_slice(&[0x13, 0xc4]); // dst port 5060
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]); // ack
        let flags = 0x10 | if psh { 0x08 } else { 0 };
        tcp.extend_from_slice(&[0x50, flags]);
        tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]); // window, csum(0), urg
        tcp.extend_from_slice(payload);

        let frag = |chunk: &[u8], off_units: u16, mf: bool| -> Packet {
            let total_len = (20 + chunk.len()) as u16;
            let frag_field = off_units | if mf { 0x2000 } else { 0 };
            let mut ip = vec![0x45, 0x00];
            ip.extend_from_slice(&total_len.to_be_bytes());
            ip.extend_from_slice(&ip_id.to_be_bytes());
            ip.extend_from_slice(&frag_field.to_be_bytes());
            ip.extend_from_slice(&[64, 6, 0, 0]); // ttl, proto=6, csum0
            ip.extend_from_slice(&[127, 0, 0, 1]); // src
            ip.extend_from_slice(&[127, 0, 0, 2]); // dst
            ip.extend_from_slice(chunk);
            let mut eth = vec![0u8; 12];
            eth.extend_from_slice(&[0x08, 0x00]); // IPv4
            eth.extend_from_slice(&ip);
            let len = eth.len();
            Packet::new(
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                eth,
                len,
                len,
                None,
                1, // DLT_EN10MB
            )
        };
        (
            frag(&tcp[..split], 0, true),
            frag(&tcp[split..], (split / 8) as u16, false),
        )
    }

    /// A SIP message spanning a normal TCP segment and an IP-fragmented TCP
    /// segment must complete: the reassembled datagram has to re-enter the
    /// TCP reassembler / SIP framer, not bypass them as a standalone unit.
    #[test]
    fn fragmented_tcp_segment_joins_stream_and_completes_spanning_message() {
        let mut proc = PacketProcessor::new();
        // Headers complete, body 5 of 10 bytes: held while the stream is open.
        let head = b"MESSAGE sip:h SIP/2.0\r\nCall-ID: span\r\nContent-Length: 10\r\n\r\nabcde";
        let out1 = proc.process(&tcp_frame(head, 1, true, false));
        assert!(out1.is_empty(), "incomplete body held, nothing emitted yet");

        // The rest of the body arrives as the next in-sequence TCP segment,
        // itself split into two IP fragments (split 24 = TCP header + 4).
        let (f1, f2) = tcp_fragment_frames(b"fghij", 1 + head.len() as u32, true, 7, 24);
        assert!(proc.process(&f1).is_empty(), "first fragment is buffered");
        let out2 = proc.process(&f2);
        assert_eq!(out2.len(), 1, "one completed SIP message expected");
        let msg = String::from_utf8_lossy(&out2[0].payload);
        assert!(
            msg.contains("Call-ID: span"),
            "held head must be joined, got: {msg}"
        );
        assert!(
            msg.ends_with("abcdefghij"),
            "full body must span the fragmented segment, got: {msg}"
        );
    }

    /// At the `max_sessions` cap the held-partial map must evict the
    /// least-recently-updated connection, not an arbitrary one — an active
    /// session's partial data must survive while the stalest entry goes.
    #[test]
    fn leftover_eviction_removes_least_recently_updated() {
        // Body incomplete (2 of 5 bytes) so the whole message is held.
        fn head(cid: &str) -> Vec<u8> {
            format!("MESSAGE sip:h SIP/2.0\r\nCall-ID: {cid}\r\nContent-Length: 5\r\n\r\nab")
                .into_bytes()
        }
        let mut proc = PacketProcessor::with_max_sessions(6);
        let h = head("a");
        for (i, port) in (6001..=6006).enumerate() {
            let cid = ["a", "b", "c", "d", "e", "f"][i];
            let out = proc.process(&tcp_frame_from(port, &head(cid), 1, true, false));
            assert!(out.is_empty(), "partial on {port} is held, not emitted");
        }
        // Refresh the first connection: one more (still incomplete) body byte,
        // making 6002 the least-recently-updated entry.
        let out = proc.process(&tcp_frame_from(6001, b"c", 1 + h.len() as u32, true, false));
        assert!(out.is_empty(), "refreshed partial still held");
        // A seventh connection overflows the cap of 6.
        let out = proc.process(&tcp_frame_from(6007, &head("g"), 1, true, false));
        assert!(out.is_empty());

        let ports: Vec<u16> = proc
            .tcp_sip_leftover
            .keys()
            .map(|(s, _)| s.port())
            .collect();
        assert_eq!(ports.len(), 6, "cap respected after eviction");
        assert!(
            ports.contains(&6001),
            "recently-updated entry must survive eviction: {ports:?}"
        );
        assert!(
            !ports.contains(&6002),
            "least-recently-updated entry is the eviction victim: {ports:?}"
        );
    }

    /// Leading zeros and surrounding whitespace in a Content-Length value
    /// still parse to the correct body length.
    #[test]
    fn frame_content_length_whitespace_and_zeros() {
        // Leading zeros and surrounding spaces in the CL value parse fine.
        let msg = b"OPTIONS sip:h SIP/2.0\r\nCall-ID: w\r\nContent-Length:  007\r\n\r\n\
                    1234567";
        let (ranges, consumed) = frame_tcp_sip(msg);
        assert_eq!(ranges.len(), 1);
        assert_eq!(consumed, msg.len(), "CL ' 007' == 7 body bytes consumed");
    }

    // ── SCTP cross-packet DATA reassembly through the pipeline ──────────
    // End-to-end proof that `PacketProcessor::process` reassembles a SIP message
    // split across SCTP DATA fragments (B/middle/E) and still passes a
    // single-packet complete (B+E) chunk straight through.

    /// Build an Ethernet/IPv4/SCTP frame (10.0.0.1 → 10.0.0.2, ports 5060/5062)
    /// carrying one DATA chunk with the given fragment `flags`, TSN, and stream
    /// seq (stream id 0).
    fn sctp_frag_frame(flags: u8, tsn: u32, ssn: u16, payload: &[u8]) -> Packet {
        // DATA chunk: type(0) flags len(2) TSN(4) SID(2) SSN(2) PPID(4) value.
        let chunk_len = 4 + 12 + payload.len();
        let mut chunk = vec![0u8, flags];
        chunk.extend_from_slice(&(chunk_len as u16).to_be_bytes());
        chunk.extend_from_slice(&tsn.to_be_bytes());
        chunk.extend_from_slice(&0u16.to_be_bytes()); // stream id
        chunk.extend_from_slice(&ssn.to_be_bytes()); // stream seq
        chunk.extend_from_slice(&0u32.to_be_bytes()); // PPID
        chunk.extend_from_slice(payload);
        while chunk.len() % 4 != 0 {
            chunk.push(0);
        }

        let mut sctp = Vec::new();
        sctp.extend_from_slice(&5060u16.to_be_bytes()); // src port
        sctp.extend_from_slice(&5062u16.to_be_bytes()); // dst port
        sctp.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // verification tag
        sctp.extend_from_slice(&0u32.to_be_bytes()); // checksum
        sctp.extend_from_slice(&chunk);

        let ip_total = (20 + sctp.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&ip_total.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 132, 0, 0]); // id, DF, ttl, proto=SCTP
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&sctp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]); // IPv4
        eth.extend_from_slice(&ip);
        let len = eth.len();
        Packet::new(
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            eth,
            len,
            len,
            None,
            1, // DLT_EN10MB
        )
    }

    /// A SIP message split across three SCTP DATA chunks (B / middle / E) in
    /// three packets is reassembled by `process`: nothing emerges until the E
    /// fragment, which yields the complete message with its ports recovered.
    #[test]
    fn process_reassembles_sctp_data_fragments() {
        let sip: &[u8] =
            b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/SCTP\r\nContent-Length: 4\r\n\r\nbody";
        let (p1, p2, p3) = (&sip[..24], &sip[24..56], &sip[56..]);
        let mut proc = PacketProcessor::new();

        assert!(
            proc.process(&sctp_frag_frame(0x02, 1, 0, p1)).is_empty(),
            "B fragment buffered, nothing emitted yet"
        );
        assert!(
            proc.process(&sctp_frag_frame(0x00, 2, 0, p2)).is_empty(),
            "middle fragment buffered, nothing emitted yet"
        );
        let out = proc.process(&sctp_frag_frame(0x01, 3, 0, p3));
        assert_eq!(out.len(), 1, "E fragment completes the reassembled message");
        assert_eq!(out[0].transport, parse::TransportProto::Sctp);
        assert_eq!((out[0].src_port, out[0].dst_port), (5060, 5062));
        assert_eq!(&out[0].payload[..], sip, "full SIP message reassembled");
    }

    /// A single-packet complete (B+E) SCTP DATA chunk still passes straight
    /// through `process` unchanged — the reassembler must not disturb it.
    #[test]
    fn process_passes_single_packet_sctp_through() {
        let sip: &[u8] = b"OPTIONS sip:h SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut proc = PacketProcessor::new();
        let out = proc.process(&sctp_frag_frame(0x03, 1, 0, sip)); // B|E
        assert_eq!(out.len(), 1, "complete chunk emitted immediately");
        assert_eq!(out[0].transport, parse::TransportProto::Sctp);
        assert_eq!((out[0].src_port, out[0].dst_port), (5060, 5062));
        assert_eq!(&out[0].payload[..], sip);
    }

    /// With `--no-reassembly` SCTP DATA fragments are not reassembled: each
    /// fragment passes through as its own (empty-payload) packet.
    #[test]
    fn no_reassembly_does_not_reassemble_sctp() {
        let mut proc = PacketProcessor::new().with_reassembly(false);
        let out = proc.process(&sctp_frag_frame(0x02, 1, 0, b"INVITE sip:h SIP/2.0"));
        assert_eq!(out.len(), 1, "fragment passes through, not buffered");
        assert!(
            out[0].payload.is_empty(),
            "no reassembly leaves the fragment payload unrecovered"
        );
    }

    // ── PacketProcessor::process dispatch (device-free) ─────────────────
    /// Tests of `PacketProcessor::process` dispatch that need no capture
    /// device: UDP pass-through, parse limits, and non-IP/garbage inputs.
    #[cfg(feature = "native")]
    mod processor {
        use super::*;
        use crate::capture::packet::Packet;
        use chrono::Utc;

        /// Minimal Ethernet + IPv4 + UDP frame carrying `payload`.
        fn eth_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
            let udp_len = 8 + payload.len() as u16;
            let ip_total = 20 + udp_len;
            let mut p = Vec::new();
            p.extend_from_slice(&[0xAA; 6]); // dst MAC
            p.extend_from_slice(&[0xBB; 6]); // src MAC
            p.extend_from_slice(&[0x08, 0x00]); // IPv4
            p.push(0x45); // ver/ihl
            p.push(0x00);
            p.extend_from_slice(&ip_total.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x01]); // id
            p.extend_from_slice(&[0x40, 0x00]); // DF, offset 0
            p.push(64); // ttl
            p.push(17); // UDP
            p.extend_from_slice(&[0x00, 0x00]); // checksum
            p.extend_from_slice(&[10, 0, 0, 1]); // src ip
            p.extend_from_slice(&[10, 0, 0, 2]); // dst ip
            p.extend_from_slice(&src_port.to_be_bytes());
            p.extend_from_slice(&dst_port.to_be_bytes());
            p.extend_from_slice(&udp_len.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x00]); // checksum
            p.extend_from_slice(payload);
            p
        }

        /// Wrap raw frame bytes `data` in a `Packet` stamped "now" with
        /// Ethernet link type.
        fn packet(data: Vec<u8>) -> Packet {
            let n = data.len();
            Packet::new(Utc::now(), data, n, n, None, 1) // linktype 1 = Ethernet
        }

        /// A plain UDP SIP packet yields exactly one parsed packet with the
        /// right transport and ports.
        #[test]
        fn udp_packet_yields_one_parsed() {
            let mut proc = PacketProcessor::new();
            let frame = eth_ipv4_udp(5060, 5060, b"REGISTER sip:x SIP/2.0\r\n\r\n");
            let out = proc.process(&packet(frame));
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].transport, parse::TransportProto::Udp);
            assert_eq!(out[0].dst_port, 5060);
        }

        /// A parse limit (`-S`/`--limitlen`) caps the emitted payload at N
        /// bytes.
        #[test]
        fn parse_limit_truncates_payload() {
            // `-S`/`--limitlen`: only the first N bytes of each message are
            // handed downstream, independent of capture snaplen.
            let mut proc = PacketProcessor::new().with_parse_limit(Some(10));
            let sip = b"REGISTER sip:x SIP/2.0\r\nCall-ID: hidden-after-limit\r\n\r\n";
            let out = proc.process(&packet(eth_ipv4_udp(5060, 5060, sip)));
            assert_eq!(out.len(), 1);
            assert_eq!(
                out[0].payload.len(),
                10,
                "payload capped to the parse limit"
            );
            assert_eq!(&out[0].payload[..], &sip[..10]);
        }

        /// Without a parse limit the full payload is preserved.
        #[test]
        fn parse_limit_none_keeps_full_payload() {
            let mut proc = PacketProcessor::new();
            let sip = b"REGISTER sip:x SIP/2.0\r\n\r\n";
            let out = proc.process(&packet(eth_ipv4_udp(5060, 5060, sip)));
            assert_eq!(out[0].payload.len(), sip.len(), "no limit → full payload");
        }

        /// A parse limit larger than the payload leaves it untouched.
        #[test]
        fn parse_limit_larger_than_payload_is_noop() {
            let mut proc = PacketProcessor::new().with_parse_limit(Some(100_000));
            let sip = b"REGISTER sip:x SIP/2.0\r\n\r\n";
            let out = proc.process(&packet(eth_ipv4_udp(5060, 5060, sip)));
            assert_eq!(
                out[0].payload.len(),
                sip.len(),
                "limit beyond payload is a no-op"
            );
        }

        /// A non-IP frame (ARP EtherType) yields no parsed packets.
        ///
        /// Keyed even though it asserts nothing about the tally: the frame it
        /// feeds is undecodable, so it BUMPS the process-global counter, and a
        /// test that asserts an exact tally must not have this running beside
        /// it.
        #[test]
        #[serial_test::serial(undecodable_tally)]
        fn non_ip_frame_yields_nothing() {
            let mut proc = PacketProcessor::with_max_sessions(16);
            // EtherType 0x0806 (ARP) — not IP, so parse yields no ParsedPacket.
            let mut frame = vec![0xAAu8; 6];
            frame.extend_from_slice(&[0xBB; 6]);
            frame.extend_from_slice(&[0x08, 0x06]); // ARP
            frame.extend_from_slice(&[0u8; 28]);
            assert!(proc.process(&packet(frame)).is_empty());
        }

        /// Bytes too short to be a valid frame hit the parse-error path and
        /// yield nothing.
        ///
        /// Keyed for the reason above: the parse error is counted.
        #[test]
        #[serial_test::serial(undecodable_tally)]
        fn truncated_garbage_yields_nothing() {
            let mut proc = PacketProcessor::new();
            // Too short to be a valid Ethernet/IP frame -> parse error path.
            assert!(proc.process(&packet(vec![0x01, 0x02, 0x03])).is_empty());
        }

        /// `sweep` on a processor with no tracked state is a safe no-op.
        #[test]
        fn sweep_is_safe_on_empty_state() {
            let mut proc = PacketProcessor::default();
            proc.sweep(); // exercises both reassembler sweeps with no entries
        }
    }

    /// The undecodable-frame tally: a frame the parser cannot turn into a
    /// [`ParsedPacket`] must be counted, by reason, with the number that
    /// identifies the reason.
    ///
    /// Every test here drives the tally through
    /// [`PacketProcessor::process`] — the real swallow site — rather than
    /// calling the recorder directly, so a wiring regression that leaves the
    /// counter correct but unreached still fails.
    ///
    /// The tally is process-global (every worker thread of the parallel
    /// pipeline has its own `PacketProcessor` and a scrape asks about the
    /// capture, not about one worker), so these tests reset it on entry and
    /// hold the `undecodable_tally` serial key.
    ///
    /// The key is shared with every other test in this binary that moves the
    /// tally or asserts on it — `capture::tests::processor`,
    /// `output::prometheus`, `output::prometheus_server`, `app::batch` and
    /// `tui::controllers::file_open`. An unkeyed `#[serial]` here would take a
    /// DIFFERENT lock from those, which is exactly the arrangement that let
    /// `for_scrape_loads_capture_quality` fail on one run in three.
    mod undecodable {
        use super::*;
        use chrono::Utc;

        /// Wrap raw frame bytes in a `Packet` with an explicit link type.
        fn packet_dlt(data: Vec<u8>, link_type: i32) -> Packet {
            let n = data.len();
            Packet::new(Utc::now(), data, n, n, None, link_type)
        }

        /// Ethernet frame whose EtherType is `et`, carrying `payload`.
        fn eth(et: u16, payload: &[u8]) -> Vec<u8> {
            let mut f = vec![0xAAu8; 6];
            f.extend_from_slice(&[0xBB; 6]);
            f.extend_from_slice(&et.to_be_bytes());
            f.extend_from_slice(payload);
            f
        }

        /// Ethernet + IPv4 frame declaring IP protocol `proto` with a 20-byte
        /// body the transport slicer will not recognize as UDP/TCP/SCTP.
        fn eth_ipv4_proto(proto: u8) -> Vec<u8> {
            let mut ip = vec![0x45u8, 0x00];
            ip.extend_from_slice(&40u16.to_be_bytes()); // total length
            ip.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, proto, 0x00, 0x00]);
            ip.extend_from_slice(&[10, 0, 0, 1]);
            ip.extend_from_slice(&[10, 0, 0, 2]);
            ip.extend_from_slice(&[0u8; 20]); // opaque protocol body
            eth(0x0800, &ip)
        }

        /// A well-formed Ethernet + ARP frame (`who-has target`): decodes
        /// cleanly and carries no IP layer, which is the `NotIp` path.
        fn eth_arp(target: [u8; 4]) -> Vec<u8> {
            let mut arp = vec![0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01];
            arp.extend_from_slice(&[0xBB; 6]); // sender MAC
            arp.extend_from_slice(&[10, 0, 0, 1]); // sender IP
            arp.extend_from_slice(&[0x00; 6]); // target MAC (unknown)
            arp.extend_from_slice(&target);
            eth(0x0806, &arp)
        }

        /// Ethernet + IPv4 + UDP frame carrying `payload` between two ports —
        /// the control case that must leave the tally untouched.
        fn eth_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
            let udp_len = 8 + payload.len() as u16;
            let mut ip = vec![0x45u8, 0x00];
            ip.extend_from_slice(&(20 + udp_len).to_be_bytes());
            ip.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, 17, 0x00, 0x00]);
            ip.extend_from_slice(&[10, 0, 0, 1]);
            ip.extend_from_slice(&[10, 0, 0, 2]);
            ip.extend_from_slice(&src_port.to_be_bytes());
            ip.extend_from_slice(&dst_port.to_be_bytes());
            ip.extend_from_slice(&udp_len.to_be_bytes());
            ip.extend_from_slice(&[0x00, 0x00]); // checksum: not computed
            ip.extend_from_slice(payload);
            eth(0x0800, &ip)
        }

        /// Feed `frames` (bytes, link type) through a fresh processor after
        /// clearing the tally, and return the report.
        fn tally(frames: &[(Vec<u8>, i32)]) -> UndecodableReport {
            reset_undecodable_frames();
            let mut proc = PacketProcessor::new();
            for (data, dlt) in frames {
                proc.process(&packet_dlt(data.clone(), *dlt));
            }
            undecodable_report()
        }

        /// A link type sipnab has no decoder for is counted, and the DLT
        /// NUMBER is carried: "unsupported link type" without the number
        /// names no capture format an operator can act on.
        #[test]
        #[serial_test::serial(undecodable_tally)]
        fn unsupported_link_type_carries_the_dlt_number() {
            let r = tally(&[
                (vec![0u8; 64], 147),
                (vec![0u8; 64], 147),
                (vec![0u8; 64], 143),
            ]);
            assert_eq!(r.frames, 3, "every frame failed to decode");
            assert_eq!(r.reasons_dropped, 0, "three reasons fit the slot table");
            assert_eq!(
                r.reasons,
                vec![
                    UndecodableTally {
                        reason: UndecodableReason::UnsupportedLinkType(147),
                        frames: 2,
                    },
                    UndecodableTally {
                        reason: UndecodableReason::UnsupportedLinkType(143),
                        frames: 1,
                    },
                ],
                "busiest reason first, each carrying its own DLT number"
            );
        }

        /// A frame that decoded but carries no IP layer takes its EtherType
        /// from what the decoder handed out — 0x8847 (MPLS) here — never from
        /// a second walk of the bytes.
        #[test]
        fn not_ip_takes_the_ethertype_it_is_given() {
            let reason = classify_undecodable(
                &CaptureError::NotIp { what: "packet" },
                FrameFacts {
                    ethertype: Some(0x8847),
                    ..FrameFacts::UNRECORDED
                },
            );
            assert_eq!(reason, Some(UndecodableReason::NotIp(Some(0x8847))));
        }

        /// With no EtherType handed out the reason says *not recorded* rather
        /// than inventing one. A wrong number stated confidently is worse than
        /// no number: it is the same defect this tally exists to remove.
        #[test]
        fn not_ip_without_a_recorded_ethertype_says_so() {
            let reason = classify_undecodable(
                &CaptureError::NotIp { what: "ARP packet" },
                FrameFacts::UNRECORDED,
            );
            assert_eq!(reason, Some(UndecodableReason::NotIp(None)));
        }

        /// "IP layer with no payload" is the not-IP family, not truncation.
        /// This is the error a well-formed ARP frame produces, and filing ARP
        /// under "truncated" would send an operator to raise a snaplen that
        /// was never the problem.
        #[test]
        fn no_ip_payload_is_not_ip_rather_than_truncation() {
            assert_eq!(
                classify_undecodable(
                    &CaptureError::NoIpPayload { what: "packet" },
                    FrameFacts {
                        ethertype: Some(0x0806),
                        ..FrameFacts::UNRECORDED
                    },
                ),
                Some(UndecodableReason::NotIp(Some(0x0806))),
            );
            assert_eq!(
                classify_undecodable(
                    &CaptureError::TooShort {
                        what: "Linux SLL2 packet",
                        need: 20,
                        got: 10,
                    },
                    FrameFacts::UNRECORDED,
                ),
                Some(UndecodableReason::Truncated),
                "a stated need/got IS truncation",
            );
        }

        /// IP that carries no transport sipnab handles takes the IP PROTOCOL
        /// number it is given — 50 (ESP) here.
        #[test]
        fn no_transport_takes_the_ip_protocol_it_is_given() {
            let reason = classify_undecodable(
                &CaptureError::NoTransport,
                FrameFacts {
                    ip_protocol: Some(50),
                    ..FrameFacts::UNRECORDED
                },
            );
            assert_eq!(reason, Some(UndecodableReason::NoTransport(Some(50))));
        }

        /// With no protocol handed out the reason says *not recorded*.
        #[test]
        fn no_transport_without_a_recorded_protocol_says_so() {
            let reason = classify_undecodable(&CaptureError::NoTransport, FrameFacts::UNRECORDED);
            assert_eq!(reason, Some(UndecodableReason::NoTransport(None)));
        }

        /// Two errors already carry their own number, so they are fully named
        /// with no help from `FrameFacts`: a GRE inner protocol IS an
        /// EtherType, and the pre-parsed (HEP) path states its IP protocol.
        #[test]
        fn errors_that_carry_their_own_number_need_no_facts() {
            assert_eq!(
                classify_undecodable(
                    &CaptureError::UnsupportedGreProtocol(0x880B),
                    FrameFacts::UNRECORDED
                ),
                Some(UndecodableReason::NotIp(Some(0x880B))),
            );
            assert_eq!(
                classify_undecodable(
                    &CaptureError::UnsupportedIpProtocol(50),
                    FrameFacts::UNRECORDED
                ),
                Some(UndecodableReason::NoTransport(Some(50))),
            );
        }

        /// End to end through the real swallow site: a frame with no IP layer
        /// and a frame with no usable transport are both counted, and both
        /// report *not recorded* while `parse_packet` hands no number back.
        ///
        /// This is the honest statement of today's plumbing. When the decoder
        /// starts handing the numbers out, the classifier gates above already
        /// pin what must then appear here.
        #[test]
        #[serial_test::serial(undecodable_tally)]
        fn unnumbered_reasons_are_counted_and_reported_as_unrecorded() {
            let r = tally(&[
                (eth_arp([10, 0, 0, 2]), 1), // ARP: decodes, carries no IP
                (eth_arp([10, 0, 0, 3]), 1), // a second ARP frame
                (eth_ipv4_proto(50), 1),     // ESP: IP, no transport sipnab handles
            ]);
            assert_eq!(r.frames, 3, "all three produced no parsed packet");
            assert_eq!(r.reasons_dropped, 0);
            assert_eq!(
                r.reasons,
                vec![
                    UndecodableTally {
                        reason: UndecodableReason::NotIp(None),
                        frames: 2,
                    },
                    UndecodableTally {
                        reason: UndecodableReason::NoTransport(None),
                        frames: 1,
                    },
                ],
                "counted and classified, with the number honestly absent"
            );
        }

        /// A frame shorter than the link header it claims is counted as
        /// truncated, not as a decode error: the remedy is a bigger snaplen,
        /// not a parser fix.
        #[test]
        #[serial_test::serial(undecodable_tally)]
        fn short_frame_counts_as_truncated() {
            // DLT_LINUX_SLL2 needs 20 header bytes; 10 is a truncated frame.
            let r = tally(&[(vec![0u8; 10], 276)]);
            assert_eq!(r.frames, 1);
            assert_eq!(
                r.reasons,
                vec![UndecodableTally {
                    reason: UndecodableReason::Truncated,
                    frames: 1,
                }]
            );
        }

        /// Bytes the decoder rejects outright are counted as a decode error.
        #[test]
        #[serial_test::serial(undecodable_tally)]
        fn rejected_bytes_count_as_a_decode_error() {
            // Three bytes on Ethernet: too short for etherparse to slice at all.
            let r = tally(&[(vec![0x01, 0x02, 0x03], 1)]);
            assert_eq!(r.frames, 1);
            assert_eq!(
                r.reasons,
                vec![UndecodableTally {
                    reason: UndecodableReason::DecodeError,
                    frames: 1,
                }]
            );
        }

        /// A packet sipnab decodes fully leaves the tally at zero. Without
        /// this the counter could read "everything failed" on a clean capture
        /// and the whole signal would be worthless.
        #[test]
        #[serial_test::serial(undecodable_tally)]
        fn a_decoded_packet_is_never_counted() {
            let r = tally(&[(
                eth_ipv4_udp(5060, 5060, b"REGISTER sip:x SIP/2.0\r\n\r\n"),
                1,
            )]);
            assert_eq!(r.frames, 0, "a decoded frame is not undecodable");
            assert!(r.reasons.is_empty());
        }

        /// ICMP is UNDERSTOOD — `parse_packet` records the quote as dialog
        /// evidence and then declines to emit a `ParsedPacket`. Counting it
        /// as undecodable would make every capture carrying an ICMP error
        /// look partly unread.
        ///
        /// Holds `icmp_evidence` as well, and the second key is not about this
        /// assertion at all. The quote below carries no payload past the UDP
        /// header, so it is not a SIP request, so `record_icmp_error` files it
        /// in the process-global MEDIA store -- and one filed quote is all it
        /// takes to raise the capture-wide ICMP section on every surface. This
        /// was the only lib test writing that store, measured by instrumenting
        /// `record_media_icmp_error` on 2026-08-26, and it held a different key
        /// from the tests that read it, so it could and did poison one of them
        /// mid-assertion. Two keys over one global is no mutual exclusion.
        #[test]
        #[serial_test::serial(undecodable_tally, icmp_evidence)]
        fn icmp_is_understood_and_not_counted() {
            // Ethernet + IPv4 + ICMP port-unreachable quoting a UDP datagram.
            let quoted = {
                let mut ip = vec![0x45u8, 0x00];
                ip.extend_from_slice(&28u16.to_be_bytes());
                ip.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00]);
                ip.extend_from_slice(&[10, 0, 0, 1]);
                ip.extend_from_slice(&[10, 0, 0, 2]);
                ip.extend_from_slice(&5060u16.to_be_bytes());
                ip.extend_from_slice(&5060u16.to_be_bytes());
                ip.extend_from_slice(&8u16.to_be_bytes());
                ip.extend_from_slice(&[0x00, 0x00]);
                ip
            };
            let mut icmp = vec![3u8, 3, 0, 0, 0, 0, 0, 0]; // dest unreachable / port
            icmp.extend_from_slice(&quoted);
            let mut ip = vec![0x45u8, 0x00];
            ip.extend_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
            ip.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 1, 0x00, 0x00]);
            ip.extend_from_slice(&[10, 0, 0, 9]);
            ip.extend_from_slice(&[10, 0, 0, 1]);
            ip.extend_from_slice(&icmp);

            let r = tally(&[(eth(0x0800, &ip), 1)]);
            assert_eq!(r.frames, 0, "ICMP is decoded, not undecodable");

            // Leave the global as it was found. The quote above is now sitting
            // in the media evidence store, and one quote is enough to raise the
            // capture-wide ICMP section on every surface that renders it. The
            // key overlapping above keeps the readers out while this runs; this
            // keeps them from finding it afterwards.
            crate::pipeline::reset_icmp_evidence();
        }

        /// More distinct numbers than the slot table holds: the TOTAL stays
        /// exact and the frames whose number was lost are reported as lost,
        /// rather than silently vanishing from the total.
        #[test]
        #[serial_test::serial(undecodable_tally)]
        fn slot_overflow_keeps_the_total_exact_and_says_what_it_lost() {
            let frames: Vec<(Vec<u8>, i32)> = (0..UNDECODABLE_REASON_SLOTS + 4)
                .map(|i| (vec![0u8; 64], 200 + i as i32))
                .collect();
            let want = frames.len() as u64;
            let r = tally(&frames);
            assert_eq!(r.frames, want, "the total counts every frame");
            assert_eq!(
                r.reasons.len(),
                UNDECODABLE_REASON_SLOTS,
                "the table holds exactly its capacity"
            );
            assert_eq!(r.reasons_dropped, 4, "the four beyond capacity are named");
            assert_eq!(
                r.reasons.iter().map(|t| t.frames).sum::<u64>() + r.reasons_dropped,
                r.frames,
                "the breakdown plus what it dropped must equal the total"
            );
        }

        /// The counter is monotonic across packets until reset, and reset
        /// returns it to zero.
        #[test]
        #[serial_test::serial(undecodable_tally)]
        fn reset_clears_the_tally() {
            let r = tally(&[(vec![0u8; 64], 147)]);
            assert_eq!(r.frames, 1);
            reset_undecodable_frames();
            let after = undecodable_report();
            assert_eq!(after.frames, 0);
            assert!(after.reasons.is_empty());
            assert_eq!(after.reasons_dropped, 0);
        }

        /// Every reason renders both a human sentence carrying its number and
        /// a stable metric label. A label without the number is the defect
        /// this whole tally exists to fix.
        #[test]
        fn reasons_render_their_number_in_both_forms() {
            let cases = [
                (
                    UndecodableReason::UnsupportedLinkType(0),
                    "unsupported link type 0",
                    "unsupported_link_type_0",
                ),
                (
                    UndecodableReason::NotIp(Some(0x8847)),
                    "not IP (EtherType 0x8847)",
                    "not_ip_ethertype_0x8847",
                ),
                (
                    UndecodableReason::NotIp(None),
                    "not IP (EtherType not recorded)",
                    "not_ip_ethertype_unrecorded",
                ),
                (
                    UndecodableReason::NoTransport(Some(50)),
                    "no transport (IP protocol 50)",
                    "no_transport_ip_protocol_50",
                ),
                (
                    UndecodableReason::NoTransport(None),
                    "no transport (IP protocol not recorded)",
                    "no_transport_ip_protocol_unrecorded",
                ),
                (
                    UndecodableReason::Truncated,
                    "truncated frame",
                    "truncated_frame",
                ),
                (
                    UndecodableReason::DecodeError,
                    "decode error",
                    "decode_error",
                ),
            ];
            for (reason, sentence, label) in cases {
                assert_eq!(reason.to_string(), sentence);
                assert_eq!(reason.label(), label);
            }
        }
    }
}
