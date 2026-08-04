// SPDX-License-Identifier: MIT OR Apache-2.0

//! Media sockets DECLARED in SDP, and the veto they hold over tunnel
//! decapsulation.
//!
//! # The problem this exists for
//!
//! `capture::tunnel::udp` decapsulates six encapsulations keyed on the
//! UDP **destination** port: L2TP 1701, GTP-U 2152, Teredo 3544, UDP-ESP 4500,
//! VXLAN 4789, Geneve 6081. A UDP port is not a protocol identity, and every
//! one of those numbers occurs in the wild as the port of an ordinary RTP
//! stream. Reading a voice payload as a tunnel header does not lose a call —
//! it **invents** one, with inner addresses and ports built out of audio
//! samples and nothing in the output marking the flow fictional.
//!
//! Structural validation is the first defence and it is a good one: five of
//! the six decoders reject an RTP packet on its first octet, because RFC 3550
//! §5.1 fixes the top two bits to `10` and each spec fixes them to something
//! else. UDP-ESP is the exception and the proven case: past the 4-octet SPI
//! every octet of an ESP datagram is ciphertext, so there is nothing left to
//! validate and a 172-byte G.711 frame satisfies every check there is.
//!
//! # SDP is a VETO, not a VOTE
//!
//! SIP already told us the truth. An SDP `m=`/`c=` pair *declares* a media
//! socket, and sipnab parses it ([`crate::sip::sdp`]) long before the media
//! arrives. This module makes that knowledge reachable from the packet-parse
//! hot path, under one rule with a deliberate asymmetry:
//!
//! - **Socket declared in SDP** → suppress decapsulation. Trust the
//!   declaration.
//! - **SDP silent** → fall back to the decoder's own structural validation.
//!   *Absence of a declaration is not evidence of tunnelling.*
//! - **A declaration may never force or assert a decapsulation.**
//!
//! The asymmetry matters because SDP is attacker-controlled. A crafted INVITE
//! carrying `m=audio 4500 RTP/AVP 0` suppresses the decapsulation of a real ESP
//! tunnel; the consequence is "missed a tunnel, counted as undecodable", which
//! is the direction this codebase already chose (see the hazard note in
//! `capture::tunnel`). If a declaration could *assert* a decap, the
//! same INVITE would make sipnab fabricate an inner flow — the failure mode the
//! whole tunnel module is written to avoid.
//!
//! That asymmetry is enforced by the **shape** of [`unless_declared`], not by
//! convention. It takes the decoder's own answer and returns the same type. It
//! is generic over an unconstrained `T`, so it has no way to construct one:
//! every `Some` it returns came from the decoder, and the only thing a
//! declaration can do is turn a `Some` into a `None`. There is no counterpart
//! function, and no `bool` a later edit could invert.
//!
//! # Why this is process-global
//!
//! `--cores N` shards packets by **outer host pair**
//! ([`crate::parallel::shard_for`] over
//! [`crate::capture::parse::peek_host_pair`]) and gives each worker its own
//! thread-local stores. SIP signalling is UA↔proxy; RTP is UA↔media-relay.
//! Those are different host pairs, so they routinely shard to different
//! workers, and the worker holding the RTP on port 4500 may never see the
//! INVITE that declared it. A per-worker registry would therefore be silently
//! useless in exactly the deployment that needs it most. The registry is one
//! process-global table, the same reasoning (and the same conclusion) as the
//! ICMP evidence store in [`crate::pipeline`].
//!
//! # The structure, and what it costs
//!
//! A **fixed 4-way set-associative table of `AtomicU64` fingerprints**:
//! `BUCKETS` buckets x `WAYS` ways = `CAPACITY` declarations, 512 KiB of
//! zero-initialised `.bss`, allocated once by the linker and never grown.
//!
//! - **Read**: one ahash of `(IpAddr, u16)`, one mask, and `WAYS` relaxed
//!   64-bit loads that all live in a single 64-byte cache line — so one cache
//!   miss per probe, no lock, no atomic read-modify-write, and no allocation.
//!   A capture that declared nothing at all pays exactly one relaxed
//!   `AtomicBool` load (`ANY_DECLARED`), the same fast path
//!   `ICMP_EVIDENCE_SEEN` gives the ICMP store.
//! - **Write**: rare — once per SDP `m=` line. Up to `2 × WAYS` relaxed loads
//!   plus one compare-exchange, on the writing thread only.
//!
//! Relaxed ordering is sufficient because the fingerprint *is* the whole
//! payload: there is no pointer, length or side allocation for it to publish,
//! so no happens-before edge is needed. A reader that misses a just-written
//! fingerprint misses a veto, which is the fall-back-to-structural-validation
//! direction.
//!
//! The alternatives were weighed and rejected. A `RwLock` read is an atomic
//! read-modify-write on one shared word, so N workers ping-pong that cache line
//! — the exact coherency cost [`crate::parallel`] batches its channel sends to
//! avoid. An immutable snapshot behind an atomic pointer swap makes reads
//! free but copies the whole set per write, which under a flood of distinct
//! `m=` lines is O(calls²) — the same cliff SNB-0015 already fixed once in
//! `StreamStore`. A fingerprint table has neither cost.
//!
//! The fingerprint seed is per-process random (`ahash::RandomState`, chosen for
//! the same flood-resistance reason `StreamStore` uses it), so an attacker
//! cannot compute a set of `m=` lines that collide into one bucket offline.
//!
//! # What is bounded, and what is evicted
//!
//! The table cannot grow: a flood of INVITEs with distinct `m=` lines consumes
//! not one byte more than the `CAPACITY` slots the binary already reserved.
//! A declaration landing in a bucket whose `WAYS` ways are all occupied
//! evicts **one way of that bucket, chosen round-robin**, and nothing else —
//! declarations in other buckets are untouchable by it. [`evictions`] counts
//! them, so overflow is observable rather than silent. An evicted declaration
//! stops vetoing, and the flow it covered falls back to structural validation.
//!
//! # Wiring
//!
//! - Write: [`declare`] belongs in `StreamStore::link_endpoint`
//!   (`src/rtp/stream_store.rs`), beside `remember_sdp_endpoint`. Every path
//!   that learns an SDP endpoint funnels through it — the single-threaded
//!   pipeline, each `--cores` worker, the TUI, and `reassociate_all`.
//! - Read: [`unless_declared`] wraps the `tunnel::udp::decap` call in
//!   `src/capture/parse.rs`.
//! - Reset: [`clear`] between captures, alongside
//!   [`crate::pipeline::reset_icmp_evidence`].

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Buckets in the table. A power of two so the index is a mask, not a modulo.
const BUCKETS: usize = 1 << 14;

/// Declarations per bucket. Four `u64`s are 32 octets, so a whole bucket is
/// read from one cache line — the reason a set-associative table beats a
/// direct-mapped one here for free: it costs the same single cache miss, and
/// it takes four colliding declarations rather than one to displace a victim.
const WAYS: usize = 4;

/// Declarations the table holds: 65,536, in 512 KiB of `.bss`.
///
/// Sized against the default `--max-streams` of 50,000, which is what one
/// `StreamStore` is already willing to track. Two `m=` lines per call makes
/// this roughly 32,000 concurrent calls' worth of declarations.
const CAPACITY: usize = BUCKETS * WAYS;

/// The value marking a slot that holds no declaration. [`nonzero`] keeps a
/// real fingerprint from ever taking it.
const EMPTY: u64 = 0;

/// The declarations, as 64-bit fingerprints of `(IpAddr, u16)`.
///
/// Zero-initialised, so it costs nothing in the binary and pages in lazily.
static TABLE: [AtomicU64; CAPACITY] = [const { AtomicU64::new(EMPTY) }; CAPACITY];

/// Whether any declaration has ever been recorded, readable without touching
/// [`TABLE`].
///
/// A capture with no SIP in it at all — a pure GTP-U or VXLAN trace, which is
/// precisely the capture the tunnel decoders exist for — must not pay a hash
/// and a cache miss per candidate datagram to be told there is nothing to
/// check. One relaxed load answers it.
static ANY_DECLARED: AtomicBool = AtomicBool::new(false);

/// Round-robin cursor choosing which way of a full bucket is overwritten.
///
/// Reset by [`clear`] so which declaration a given capture drops is a function
/// of the bytes, not of whatever the process did beforehand.
static VICTIM: AtomicU32 = AtomicU32::new(0);

/// Decapsulations suppressed because a socket was declared.
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Declarations dropped because their bucket was full.
static EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// Record a media socket that an SDP `m=`/`c=` pair declared.
///
/// Idempotent, and cheap enough to call for every `m=` line of every
/// offer and answer. Safe to call from any thread.
///
/// Two kinds of `m=` line are deliberately **not** recorded, because neither
/// names a socket and recording them would spend a bounded slot on an
/// attacker's behalf:
///
/// - `port == 0` — RFC 3264 §8.2 makes a zero port a *rejection* of the
///   stream, and §8.4 the way to disable one. There is no socket to protect.
/// - An unspecified address (`0.0.0.0`, `::`) — the classic hold indication;
///   no datagram ever arrives at one.
///
/// # Arguments
///
/// * `addr` — the effective connection address for the media section (media
///   level `c=` if present, else session level; see
///   [`crate::sip::sdp::effective_address`]).
/// * `port` — the `m=` line's transport port.
///
/// # Side effects
///
/// Inserts a fingerprint of `(addr, port)` into the process-global table,
/// possibly evicting one way of its bucket (counted by [`evictions`]), and
/// arms the `ANY_DECLARED` fast path.
pub fn declare(addr: IpAddr, port: u16) {
    if port == 0 || addr.is_unspecified() {
        return;
    }
    let fp = fingerprint(addr, port);
    let bucket = ways(bucket_for(fp));

    // Already known: the overwhelmingly common case, because an offer, its
    // answer, and every re-INVITE all name the same sockets again.
    for slot in bucket {
        if slot.load(Ordering::Relaxed) == fp {
            ANY_DECLARED.store(true, Ordering::Release);
            return;
        }
    }
    // A free way. Two threads declaring the same socket at once can both miss
    // the scan above and land in two ways; that wastes a slot and changes no
    // answer, since both compare equal on lookup.
    for slot in bucket {
        if slot
            .compare_exchange(EMPTY, fp, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            ANY_DECLARED.store(true, Ordering::Release);
            return;
        }
    }
    // Full. Overwrite one way of THIS bucket and nothing else.
    let victim = (VICTIM.fetch_add(1, Ordering::Relaxed) as usize) & (WAYS - 1);
    bucket[victim].store(fp, Ordering::Relaxed);
    EVICTIONS.fetch_add(1, Ordering::Relaxed);
    ANY_DECLARED.store(true, Ordering::Release);
}

/// Pass a decapsulation result through, **unless** SDP declared one of the two
/// sockets to be media — in which case there is no tunnel and the result is
/// dropped.
///
/// This is the only query this module offers, and the only answer it can give
/// is "no". It cannot construct a `T`, so it can never report a tunnel the
/// decoder did not itself find: a declaration is a veto over the decoder, never
/// a substitute for it. `decoded == None` returns `None` without consulting the
/// registry at all — there is nothing to veto, and nothing to count.
///
/// Both sockets are checked, destination first. SDP declares where an endpoint
/// wants to *receive*, but NAT and asymmetric RTP mean the declared socket is
/// just as often the observed **source** — a UA sending from its declared media
/// port toward a relay. Each socket is also matched against the RFC 3550 §11
/// RTCP companion rule: an even media port carries RTP and the next port up
/// carries RTCP, and no `m=` line ever mentions that second port. The rule here
/// is the same one, in the same form, as
/// [`StreamStore::attribute_media_quote`](crate::rtp::stream_store::StreamStore::attribute_media_quote)
/// tier 4 — one rule, so the two cannot drift.
///
/// An RTCP port moved elsewhere by `a=rtcp:<port>` (RFC 3605) is not covered by
/// the companion rule and is only vetoed if the caller declared it in its own
/// right. The consequence is a missed veto, which is the safe direction.
///
/// # Arguments
///
/// * `decoded` — what the decapsulator concluded, unchanged if nothing is
///   declared.
/// * `src` / `dst` — the OUTER datagram's sockets, as parsed from the IP and
///   UDP headers.
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// use sipnab::capture::declared_media::{clear, declare, unless_declared};
///
/// clear();
/// let media: IpAddr = Ipv4Addr::new(203, 0, 113, 5).into();
/// let phone: IpAddr = Ipv4Addr::new(198, 51, 100, 7).into();
///
/// // The SDP said this socket carries audio.
/// declare(media, 4500);
///
/// // A G.711 frame to it passes every ESP check there is; the declaration
/// // says it is voice, so the "tunnel" is dropped.
/// let to_media = SocketAddr::new(media, 4500);
/// let from_phone = SocketAddr::new(phone, 40000);
/// assert_eq!(unless_declared(Some("esp"), from_phone, to_media), None);
///
/// // A socket nobody declared is left to the decoder's own validation:
/// // silence is not evidence of tunnelling.
/// let undeclared = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 6).into(), 4500);
/// assert_eq!(unless_declared(Some("esp"), from_phone, undeclared), Some("esp"));
/// clear();
/// ```
#[inline]
#[must_use]
pub fn unless_declared<T>(decoded: Option<T>, src: SocketAddr, dst: SocketAddr) -> Option<T> {
    // Nothing to veto. Costs one branch on every non-tunnel datagram.
    let decoded = decoded?;
    // No SDP anywhere in this capture: one relaxed load and out.
    if !ANY_DECLARED.load(Ordering::Acquire) {
        return Some(decoded);
    }
    for socket in [dst, src] {
        if declared(socket) {
            SUPPRESSED.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    }
    Some(decoded)
}

/// How many decapsulations [`unless_declared`] has suppressed.
///
/// For the reporting layer only. It is deliberately a count and not a
/// predicate: nothing can branch on it back into a decapsulation.
#[must_use]
pub fn suppressed() -> u64 {
    SUPPRESSED.load(Ordering::Relaxed)
}

/// How many declarations have been evicted because their bucket was full.
///
/// Non-zero means the registry overflowed and some flows fell back to
/// structural validation — worth surfacing rather than discovering later.
#[must_use]
pub fn evictions() -> u64 {
    EVICTIONS.load(Ordering::Relaxed)
}

/// Forget every declaration and reset the counters.
///
/// For the boundary between captures in a long-lived process (the MCP server,
/// the TUI opening a second file), where a declaration from the previous
/// capture must not suppress a tunnel in the next one. Not a concurrent
/// operation: call it when no capture is running, exactly as
/// [`crate::pipeline::reset_icmp_evidence`] is called.
pub fn clear() {
    for slot in &TABLE {
        slot.store(EMPTY, Ordering::Relaxed);
    }
    VICTIM.store(0, Ordering::Relaxed);
    SUPPRESSED.store(0, Ordering::Relaxed);
    EVICTIONS.store(0, Ordering::Relaxed);
    // Last, so a reader that still sees the armed flag finds an empty table
    // rather than a half-cleared one.
    ANY_DECLARED.store(false, Ordering::Release);
}

/// Whether `socket`, or the declared media port it is the RFC 3550 §11 RTCP
/// companion of, was declared.
fn declared(socket: SocketAddr) -> bool {
    // RFC 3550 §11: RTP on an even port, RTCP on the next one up. So an
    // observed ODD port may be the companion of the even port below it, and
    // that even port is what an `m=` line named. Identical in form to
    // `StreamStore::attribute_media_quote`.
    let companion = socket.port().checked_sub(1).filter(|p| p % 2 == 0);
    [Some(socket.port()), companion]
        .into_iter()
        .flatten()
        .any(|port| contains(socket.ip(), port))
}

/// Whether `(addr, port)` is in the table.
fn contains(addr: IpAddr, port: u16) -> bool {
    let fp = fingerprint(addr, port);
    ways(bucket_for(fp))
        .iter()
        .any(|slot| slot.load(Ordering::Relaxed) == fp)
}

/// The [`WAYS`] slots of one bucket, contiguous and cache-line aligned by
/// construction.
fn ways(bucket: usize) -> &'static [AtomicU64] {
    let base = bucket * WAYS;
    &TABLE[base..base + WAYS]
}

/// Bucket index carried by a fingerprint.
fn bucket_for(fp: u64) -> usize {
    (fp as usize) & (BUCKETS - 1)
}

/// Bucket a socket's fingerprint falls in. Tests use it to build a set of
/// colliding declarations without hardcoding anything against the per-process
/// random seed.
#[cfg(test)]
fn bucket_of(addr: IpAddr, port: u16) -> usize {
    bucket_for(fingerprint(addr, port))
}

/// The 64-bit fingerprint of a socket.
///
/// The full width is stored and the full width is compared, so a false match
/// needs a genuine 64-bit collision. Should one ever happen it suppresses a
/// decapsulation that structural validation would have allowed — the safe
/// direction, again.
fn fingerprint(addr: IpAddr, port: u16) -> u64 {
    /// Per-process random seed. `ahash` for the same reason `StreamStore`
    /// uses it: fast, and randomly seeded so attacker-chosen keys cannot be
    /// collided offline.
    static SEED: OnceLock<ahash::RandomState> = OnceLock::new();
    // Called through the trait by path, not as `state.hash_one(..)`. `ahash`
    // also carries an INHERENT `hash_one` under some of its feature flags, and
    // which of the two a bare method call resolves to then depends on the
    // feature combination the crate is built with — 11 of them in CI.
    nonzero(std::hash::BuildHasher::hash_one(
        SEED.get_or_init(ahash::RandomState::new),
        (addr, port),
    ))
}

/// Move a raw hash off the [`EMPTY`] marker, so no real declaration can be
/// mistaken for a free slot. Costs one branch and one in 2⁶⁴ fingerprints
/// their last bit of distinctness.
fn nonzero(h: u64) -> u64 {
    if h == EMPTY { 1 } else { h }
}

/// Tests for the SDP declaration registry: what vetoes, what does not, the
/// RFC 3550 §11 RTCP companion rule, both directions, the fixed bound, and the
/// asymmetry that keeps a declaration from ever asserting a decapsulation.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Start from an empty registry with zeroed counters, so every assertion
    /// below can name an exact value.
    ///
    /// Every caller carries `#[serial_test::serial(declared_media)]`, which is
    /// what makes the reset meaningful: the registry is process-global — that
    /// is the whole point, see the module docs on `--cores` — so a test that
    /// cleared it must not have another declaring into it. A named key rather
    /// than a module-private mutex, both to match the convention this codebase
    /// already uses for its other process-global state (`icmp_evidence`,
    /// `kernel_drop_counts`, `undecodable_tally`) and so that the tests which
    /// will exercise the registry from `capture::parse` and
    /// `rtp::stream_store`, once [`unless_declared`] and [`declare`] are wired
    /// in there, can take the same lock from another module.
    fn fixture() {
        clear();
    }

    /// An IPv4 `IpAddr` from four octets.
    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Stand-in for a decapsulator's answer. Deliberately not `tunnel::Inner`:
    /// `unless_declared` is generic and must not know what it is filtering.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Decoded(u32);

    /// A socket the SDP declared vetoes the decapsulation of a datagram sent
    /// TO it, and the suppression is counted exactly once.
    #[test]
    #[serial_test::serial(declared_media)]
    fn a_declared_destination_socket_vetoes_the_decapsulation() {
        fixture();
        let media = v4(203, 0, 113, 5);
        declare(media, 4500);

        let dst = SocketAddr::new(media, 4500);
        let src = SocketAddr::new(v4(198, 51, 100, 7), 40000);
        assert_eq!(unless_declared(Some(Decoded(1)), src, dst), None);
        assert_eq!(suppressed(), 1);
    }

    /// A socket no SDP declared is left entirely to the decoder's own
    /// structural validation. Absence of a declaration is not evidence.
    #[test]
    #[serial_test::serial(declared_media)]
    fn an_undeclared_socket_is_left_to_the_decoders_own_validation() {
        fixture();
        declare(v4(203, 0, 113, 5), 4500);
        let src = SocketAddr::new(v4(198, 51, 100, 7), 40000);

        // Same port, different host.
        let other_host = SocketAddr::new(v4(203, 0, 113, 6), 4500);
        assert_eq!(
            unless_declared(Some(Decoded(7)), src, other_host),
            Some(Decoded(7))
        );
        // Same host, different port.
        let other_port = SocketAddr::new(v4(203, 0, 113, 5), 2152);
        assert_eq!(
            unless_declared(Some(Decoded(9)), src, other_port),
            Some(Decoded(9))
        );
        assert_eq!(suppressed(), 0);
    }

    /// The RTCP companion of a declared EVEN port vetoes too, and a declared
    /// ODD port has no companion — the same rule, and the same parity test,
    /// as `StreamStore::attribute_media_quote`.
    #[test]
    #[serial_test::serial(declared_media)]
    fn the_rtcp_companion_of_an_even_declaration_vetoes_and_an_odd_one_has_none() {
        fixture();
        let media = v4(203, 0, 113, 5);
        let src = SocketAddr::new(v4(198, 51, 100, 7), 40000);

        declare(media, 4788);
        assert_eq!(
            unless_declared(Some(Decoded(1)), src, SocketAddr::new(media, 4789)),
            None
        );
        assert_eq!(suppressed(), 1);
        // Two above the declared port is nobody's companion.
        assert_eq!(
            unless_declared(Some(Decoded(2)), src, SocketAddr::new(media, 4790)),
            Some(Decoded(2))
        );
        assert_eq!(suppressed(), 1);

        clear();
        declare(media, 4789);
        // 4789 is odd, so 4790 is not its companion — RFC 3550 §11 pairs an
        // EVEN RTP port with the next one up, never an odd one.
        assert_eq!(
            unless_declared(Some(Decoded(3)), src, SocketAddr::new(media, 4790)),
            Some(Decoded(3))
        );
        assert_eq!(suppressed(), 0);
        // The declared port itself still vetoes.
        assert_eq!(
            unless_declared(Some(Decoded(4)), src, SocketAddr::new(media, 4789)),
            None
        );
        assert_eq!(suppressed(), 1);
    }

    /// The declared socket is where an endpoint RECEIVES; NAT and asymmetric
    /// RTP mean it is routinely the SOURCE of the datagram being examined, so
    /// both sockets are checked.
    #[test]
    #[serial_test::serial(declared_media)]
    fn a_declared_source_socket_vetoes_too() {
        fixture();
        let ua = v4(198, 51, 100, 7);
        declare(ua, 16400);

        let src = SocketAddr::new(ua, 16400);
        let dst = SocketAddr::new(v4(203, 0, 113, 9), 2152);
        assert_eq!(unless_declared(Some(Decoded(1)), src, dst), None);
        assert_eq!(suppressed(), 1);
    }

    /// A bucket holds exactly FOUR declarations. The fifth evicts exactly one
    /// — the oldest way, because `clear` resets the round-robin cursor — and
    /// everything newer survives.
    ///
    /// The counts here are literals on purpose. Written against `WAYS` the
    /// test re-derives the bound it is supposed to pin, so widening the
    /// associativity would leave it green.
    #[test]
    #[serial_test::serial(declared_media)]
    fn a_full_bucket_holds_four_and_the_fifth_evicts_exactly_one() {
        fixture();

        // The fingerprint seed is per-process random, so a colliding set is
        // DISCOVERED here, never hardcoded. The search runs over a whole /8
        // rather than the port space: 65,536 ports over `BUCKETS` buckets
        // average only four per bucket, so looking for five of them there is
        // a coin toss, and the test would flake.
        let port = 20000u16;
        let target = bucket_of(v4(10, 0, 0, 1), port);
        let mut hosts: Vec<IpAddr> = Vec::new();
        for i in 0..(1u32 << 24) {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
            if bucket_of(ip, port) == target {
                hosts.push(ip);
                if hosts.len() == 5 {
                    break;
                }
            }
        }
        assert_eq!(hosts.len(), 5, "need a full bucket plus one");

        for ip in &hosts {
            declare(*ip, port);
        }
        assert_eq!(evictions(), 1);
        assert!(!contains(hosts[0], port), "the oldest way is the victim");
        let kept = hosts.iter().filter(|ip| contains(**ip, port)).count();
        assert_eq!(kept, 4);
    }

    /// A flood of distinct `m=` lines cannot grow the registry by one byte:
    /// the table is a fixed 512 KiB, so every declaration past a full bucket
    /// evicts one already in it and none is ever allocated.
    #[test]
    #[serial_test::serial(declared_media)]
    fn a_flood_of_distinct_declarations_cannot_grow_the_registry() {
        fixture();
        let ip = v4(192, 0, 2, 2);
        for p in 1..=u16::MAX {
            declare(ip, p);
        }
        // Every declaration either took a free way or displaced one.
        let kept = (1..=u16::MAX).filter(|p| contains(ip, *p)).count();
        assert_eq!(kept + evictions() as usize, 65_535);
        // …and the ceiling it worked against is a compile-time constant.
        assert_eq!(CAPACITY, 65_536);
        assert_eq!(std::mem::size_of_val(&TABLE), 512 * 1024);
    }

    /// The registry can only ever REMOVE a decapsulation. With both sockets
    /// declared and the decoder saying no, the answer is still no — and the
    /// `Infallible` instantiation says so statically: `unless_declared` is
    /// generic over an unconstrained `T`, so it has no way to build one.
    #[test]
    #[serial_test::serial(declared_media)]
    fn a_declaration_can_never_create_a_decapsulation() {
        fixture();
        let ip = v4(203, 0, 113, 5);
        declare(ip, 4500);
        let s = SocketAddr::new(ip, 4500);

        assert_eq!(unless_declared::<Decoded>(None, s, s), None);
        assert_eq!(
            unless_declared::<std::convert::Infallible>(None, s, s),
            None
        );
        assert_eq!(suppressed(), 0);
    }

    /// `clear` forgets every declaration and both counters, so a second
    /// capture in one process starts from nothing.
    #[test]
    #[serial_test::serial(declared_media)]
    fn clear_forgets_every_declaration() {
        fixture();
        let ip = v4(203, 0, 113, 5);
        declare(ip, 4500);
        assert!(contains(ip, 4500));

        let s = SocketAddr::new(ip, 4500);
        assert_eq!(unless_declared(Some(Decoded(1)), s, s), None);
        assert_eq!(suppressed(), 1);

        clear();
        assert!(!contains(ip, 4500), "clear must drop the declaration");
        assert_eq!(suppressed(), 0);
        assert_eq!(evictions(), 0);
        assert_eq!(
            unless_declared(Some(Decoded(2)), s, s),
            Some(Decoded(2)),
            "a cleared declaration must stop vetoing"
        );
    }

    /// A rejected or held media line is not a socket and is not recorded:
    /// port 0 (RFC 3264 §8.2 rejection) and the unspecified address (the
    /// classic hold indication) both consume no slot.
    #[test]
    #[serial_test::serial(declared_media)]
    fn a_rejected_or_held_media_line_is_not_recorded() {
        fixture();
        let host = v4(203, 0, 113, 5);

        declare(host, 0);
        assert!(!contains(host, 0), "a zero port rejects the stream");
        declare(v4(0, 0, 0, 0), 4500);
        assert!(!contains(v4(0, 0, 0, 0), 4500), "0.0.0.0 is not a socket");
        declare(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 4500);
        assert!(
            !contains(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 4500),
            ":: is not a socket"
        );

        // Port 1's companion probe is port 0; nothing may ever live there.
        let s = SocketAddr::new(host, 1);
        assert_eq!(
            unless_declared(Some(Decoded(1)), s, s),
            Some(Decoded(1)),
            "the companion probe must not find a phantom port 0"
        );
        assert_eq!(suppressed(), 0);
    }

    /// An IPv6 media socket vetoes on its own terms and does not alias the
    /// same-numbered IPv4 port.
    #[test]
    #[serial_test::serial(declared_media)]
    fn an_ipv6_media_socket_vetoes_independently_of_ipv4() {
        fixture();
        let six: IpAddr = "2001:db8::5".parse().expect("valid IPv6 literal");
        declare(six, 6081);

        let src = SocketAddr::new(
            "2001:db8::7".parse::<IpAddr>().expect("valid IPv6 literal"),
            40000,
        );
        assert_eq!(
            unless_declared(Some(Decoded(1)), src, SocketAddr::new(six, 6081)),
            None
        );
        assert_eq!(suppressed(), 1);

        let four = SocketAddr::new(v4(203, 0, 113, 5), 6081);
        assert_eq!(
            unless_declared(Some(Decoded(2)), src, four),
            Some(Decoded(2)),
            "an IPv6 declaration must not veto an IPv4 socket"
        );
        assert_eq!(suppressed(), 1);
    }

    /// `--cores` shards by OUTER HOST PAIR, so the worker that parses the
    /// INVITE is routinely not the worker that later sees the media. A
    /// declaration made on one thread must veto on another.
    #[test]
    #[serial_test::serial(declared_media)]
    fn a_declaration_on_one_worker_vetoes_on_another() {
        fixture();
        let media = v4(203, 0, 113, 5);

        let signalling = std::thread::spawn(move || declare(media, 4500));
        signalling.join().expect("signalling worker must finish");

        let media_worker = std::thread::spawn(move || {
            let dst = SocketAddr::new(media, 4500);
            let src = SocketAddr::new(v4(198, 51, 100, 7), 40000);
            unless_declared(Some(Decoded(1)), src, dst)
        });
        assert_eq!(
            media_worker.join().expect("media worker must finish"),
            None,
            "a per-worker registry would silently miss this"
        );
        assert_eq!(suppressed(), 1);
    }

    /// Zero marks an empty slot, so no fingerprint may ever be zero.
    #[test]
    fn a_fingerprint_is_never_the_empty_marker() {
        assert_eq!(nonzero(0), 1);
        assert_eq!(nonzero(1), 1);
        assert_eq!(nonzero(0x0123_4567_89ab_cdef), 0x0123_4567_89ab_cdef);
        assert_eq!(nonzero(u64::MAX), u64::MAX);
    }
}
