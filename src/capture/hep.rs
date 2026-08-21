// SPDX-License-Identifier: MIT OR Apache-2.0

//! HEP (Homer Encapsulation Protocol) v2/v3 receiver and sender.
//!
//! HEP is used by SIP servers (OpenSIPS, Kamailio, FreeSWITCH, etc.) to mirror
//! SIP traffic to a capture server. sipnab acts as a HEP receiver (like
//! Homer/heplify-server) when invoked with `-L`, and as a HEP sender when
//! invoked with `-H`.
//!
//! ## Wire formats
//!
//! **HEP v3** (RFC-style, chunk-based):
//! ```text
//! "HEP3" magic (4 bytes) | total length (2 bytes, big-endian)
//! followed by variable-length chunks, each:
//!   vendor_id (2) | type (2) | length (2, includes 6-byte header) | data (N)
//! ```
//!
//! **HEP v2** (legacy, fixed header):
//! ```text
//! version (1 byte, 0x02) | header_length (1 byte)
//! src_port (2) | dst_port (2) | src_ip (4) | dst_ip (4)
//! payload follows immediately after the header
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::{Duration, Instant};

use super::channel::PacketTx;
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, TimeZone, Utc};

use super::CaptureConfig;
use super::packet::{Packet, PreParsed};
use crate::net::TransportProto;
use crate::signals;

// ── HEP v3 chunk type constants (vendor 0x0000) ─────────────────────

/// Chunk type: IP protocol family (1 byte: 2=IPv4, 10=IPv6).
const CHUNK_IP_FAMILY: u16 = 0x0001;
/// Chunk type: IP protocol ID (1 byte: 6=TCP, 17=UDP).
const CHUNK_IP_PROTO: u16 = 0x0002;
/// Chunk type: Source IPv4 address (4 bytes).
const CHUNK_SRC_IPV4: u16 = 0x0003;
/// Chunk type: Destination IPv4 address (4 bytes).
const CHUNK_DST_IPV4: u16 = 0x0004;
/// Chunk type: Source IPv6 address (16 bytes).
const CHUNK_SRC_IPV6: u16 = 0x0005;
/// Chunk type: Destination IPv6 address (16 bytes).
const CHUNK_DST_IPV6: u16 = 0x0006;
/// Chunk type: Source port (2 bytes, big-endian).
const CHUNK_SRC_PORT: u16 = 0x0007;
/// Chunk type: Destination port (2 bytes, big-endian).
const CHUNK_DST_PORT: u16 = 0x0008;
/// Chunk type: Timestamp seconds since epoch (4 bytes, big-endian).
const CHUNK_TS_SEC: u16 = 0x0009;
/// Chunk type: Timestamp microseconds (4 bytes, big-endian).
const CHUNK_TS_USEC: u16 = 0x000a;
/// Chunk type: Protocol type (1 byte: 1=SIP, 5=RTCP, 32=RTP).
const CHUNK_PROTO_TYPE: u16 = 0x000b;
/// Chunk type: Capture agent ID (4 bytes, big-endian).
const CHUNK_CAPTURE_ID: u16 = 0x000c;
/// Chunk type: Authenticate key / password (variable length) — Homer's
/// per-capture-agent shared secret.
const CHUNK_AUTH_KEY: u16 = 0x000e;
/// Chunk type: Payload — the actual SIP/RTP message (variable length).
const CHUNK_PAYLOAD: u16 = 0x000f;
/// Chunk type: Correlation ID — typically the Call-ID (variable length).
const CHUNK_CORRELATION_ID: u16 = 0x0011;

/// HEP v3 magic bytes.
const HEP3_MAGIC: &[u8; 4] = b"HEP3";
/// HEP v3 fixed header length (magic + total length).
const HEP3_HEADER_LEN: usize = 6;
/// Minimum chunk size: 6-byte header with no data.
const CHUNK_HEADER_LEN: usize = 6;

/// HEP v2 version byte.
const HEP2_VERSION: u8 = 0x02;
/// Minimum HEP v2 header length for IPv4 (version + hdr_len + ports + IPs).
const HEP2_MIN_HEADER: usize = 16;

// ── HEP→Packet conversion ────────────────────────────────────────────

/// Convert a parsed [`HepPacket`] into a [`Packet`] tagged with
/// `pre_parsed` metadata. The downstream parser short-circuits on
/// `pre_parsed`, treating `data` as the transport-layer payload only
/// — no link-layer or IP/UDP/TCP headers are fabricated. The HEP
/// chunks (src/dst addr, src/dst port, IP protocol) flow straight
/// into [`PreParsed`].
///
/// Without this, a HEP-sourced packet would arrive at the parser as
/// `link_type = DLT_RAW` plus payload-only data, which `etherparse`
/// would mis-interpret as an IPv4 header (e.g. `INVITE`'s first byte
/// `0x49` parses as IPv4 IHL=9), silently dropping every HEP message.
///
/// # Arguments
///
/// * `hep` — the parsed HEP packet whose payload and metadata to convert.
/// * `source` — listener bind address, recorded as interface `"hep:{source}"`.
///
/// # Returns
///
/// A `Packet` whose `data` is the HEP payload and whose `pre_parsed`
/// carries the HEP-asserted addressing.
/// Identify the SENDER of a HEP packet — the node whose traffic this is —
/// rather than the listener that received it.
///
/// The listener used to record its own bind address, so a collector fed by an
/// SBC and two PBXes labeled every dialog `hep:0.0.0.0:9060`. Every node
/// collapsed into one identity, and "which node did this leg come from" had no
/// answer even though the answer arrived in the packet: HEP chunk 0x000c
/// carries the sender's capture-agent id (`--hep-id`), and the datagram's peer
/// address says where it came from. Both were parsed and discarded.
///
/// The id alone is not enough — it defaults to 1, so an estate that never sets
/// it would collapse again — and the address alone is not enough either, since
/// two sipnab instances can share a host. Both, so neither collision hides a
/// node.
pub(crate) fn hep_source_label(capture_id: Option<u32>, peer: IpAddr) -> String {
    match capture_id {
        Some(id) => format!("{id}@{peer}"),
        None => peer.to_string(),
    }
}

/// Turn a parsed HEP packet into a `Packet` the rest of the pipeline accepts.
///
/// The inner addresses and ports come from the HEP chunks rather than an IP
/// header walk, and `source` names where the frame came from — see
/// [`hep_source_label`], which is what makes a multi-node fan-in
/// distinguishable.
fn hep_to_packet(hep: HepPacket, source: &str) -> Packet {
    Packet::with_pre_parsed(
        hep.timestamp,
        hep.payload,
        Some(format!("hep:{source}")),
        PreParsed {
            src_addr: hep.src_addr,
            dst_addr: hep.dst_addr,
            src_port: hep.src_port,
            dst_port: hep.dst_port,
            ip_protocol: hep.ip_protocol,
        },
    )
}

/// One listener's frame numbering, kept per SENDER.
///
/// A HEP listener is a fan-in: one socket, many nodes. Ordinals are per source
/// and a source here is a sender, not the listener — the same distinction
/// [`hep_source_label`] exists to make. One listener-wide counter would number
/// an SBC's frames with a PBX's positions, so every pointer either side minted
/// would name a gap, and following one would find nothing where a real frame
/// was claimed to be.
///
/// # Why the table is bounded, and why it refuses instead of recycling
///
/// The label is built from the sender's capture-agent id, which absent
/// `--hep-auth` is a number an unauthenticated peer chooses freely — so one
/// host can mint unbounded distinct labels and this map is attacker-growable
/// exactly as the rate limiter's peer table is. It therefore shares that
/// table's bound.
///
/// At the bound a new sender gets NO ordinal rather than a recycled counter.
/// Recycling would mint a second frame 0 for a source that already had one:
/// two different datagrams with the same name, which is precisely the
/// confident wrong answer the pointer system exists to prevent.
/// [`crate::capture::packet::Packet::frame_ref`] already needs both halves, so
/// an unstamped packet reports "unknown" downstream, which is true.
struct HepFrameOrdinals {
    /// Source label (`<capture-id>@<peer>`) to that sender's own counter.
    counters: std::collections::HashMap<String, crate::capture::packet::FrameCounter>,
    /// Distinct senders this listener will number, matching the rate
    /// limiter's per-peer bound.
    max_sources: usize,
}

impl HepFrameOrdinals {
    /// A listener that will number at most `max_sources` distinct senders.
    fn new(max_sources: usize) -> Self {
        Self {
            counters: std::collections::HashMap::new(),
            max_sources,
        }
    }

    /// Where the next frame from `source` sits in that sender's own stream, or
    /// `None` once this listener is already numbering `max_sources` senders
    /// and this is a new one.
    fn next_origin(&mut self, source: &str) -> Option<crate::capture::packet::FrameOrigin> {
        if let Some(counter) = self.counters.get_mut(source) {
            return Some(counter.next_origin());
        }
        if self.counters.len() >= self.max_sources {
            return None;
        }
        Some(
            self.counters
                .entry(source.to_string())
                .or_default()
                .next_origin(),
        )
    }
}

// ── Receiver-side authentication & bind policy ───────────────────────

/// Decide whether a received HEP packet's auth-key chunk satisfies the
/// configured receiver secret.
///
/// * `expected = None` — no receiver secret configured: accept everything
///   (backward compatible; HEP was previously unauthenticated on receive).
/// * `expected = Some(secret)` — the packet must carry an auth-key chunk
///   whose bytes equal `secret`. A missing chunk or any mismatch is
///   rejected. The comparison is constant time so a network attacker
///   cannot recover the secret byte-by-byte from timing (SN-01, CWE-345).
///
/// # Arguments
///
/// * `expected` — the configured receiver secret, if any.
/// * `presented` — the raw bytes of the packet's `0x000e` auth-key chunk,
///   if the packet carried one.
///
/// # Returns
///
/// `true` when the packet should be accepted, `false` when it must be
/// dropped.
pub fn hep_auth_ok(expected: Option<&str>, presented: Option<&[u8]>) -> bool {
    match expected {
        None => true,
        Some(secret) => match presented {
            Some(bytes) => crate::crypto::constant_time_eq(secret.as_bytes(), bytes),
            None => false,
        },
    }
}

/// Enforce the HEP listener bind policy, mirroring the REST API / MCP HTTP
/// rule (D18): a non-loopback bind is refused unless the deployment has
/// constrained who or what it will trust — either receiver-side
/// authentication (`has_auth`) or a non-empty source allowlist
/// (`allowlist_len > 0`). A loopback bind is always permitted.
///
/// Loopback is determined purely syntactically (`hep_bind_is_loopback`):
/// a hostname is not resolved and counts as non-loopback, so an unguarded
/// hostname bind is refused (fail closed).
///
/// # Arguments
///
/// * `bind_addr` — the listener bind address (host:port form).
/// * `has_auth` — whether a receiver-side shared secret is configured.
/// * `allowlist_len` — number of configured source CIDR ranges.
///
/// # Errors
///
/// Returns a human-readable refusal message when `bind_addr` is
/// non-loopback and neither `has_auth` nor a non-empty allowlist applies.
pub fn enforce_hep_bind_policy(
    bind_addr: &str,
    has_auth: bool,
    allowlist_len: usize,
) -> Result<(), String> {
    if has_auth || allowlist_len > 0 {
        return Ok(());
    }
    if hep_bind_is_loopback(bind_addr) {
        return Ok(());
    }
    Err(format!(
        "HEP listener refuses to start: --hep-listen {bind_addr} is non-loopback but \
         neither a shared secret (--hep-auth / --hep-auth-file) nor a source allowlist \
         (--hep-allow) was configured. Bind to 127.0.0.1, add an allowlist, or set a \
         secret to accept HEP from a routable address."
    ))
}

/// Whether `bind_addr` is a loopback address, decided **purely
/// syntactically**. Only a literal IP (in `IP:port` form, including the
/// bracketed IPv6 form) is classified; a hostname is *not* resolved.
///
/// A DNS lookup inside this security decision could block startup or be
/// steered by a spoofed record, so a non-literal address is treated
/// conservatively as non-loopback (fail closed). Callers that bind to a
/// hostname get a startup warning suggesting a literal (see [`capture_hep`]).
fn hep_bind_is_loopback(bind_addr: &str) -> bool {
    match bind_addr.parse::<std::net::SocketAddr>() {
        Ok(addr) => addr.ip().is_loopback(),
        Err(_) => false,
    }
}

/// Whether `bind_addr` is a literal socket address (`IP:port`, including the
/// bracketed IPv6 form) rather than a hostname. Purely syntactic — it never
/// performs name resolution.
fn hep_bind_is_ip_literal(bind_addr: &str) -> bool {
    bind_addr.parse::<std::net::SocketAddr>().is_ok()
}

// ── Per-peer rate-limit ergonomics ───────────────────────────────────

/// One-line description of the active HEP rate limiters for the startup
/// log, so an operator can see at a glance whether the per-peer cap is on.
///
/// `global` is the packets/second ceiling across all peers; `per_peer` is
/// the per-source cap. Either knob renders as "disabled" when 0, so both read
/// consistently. Returns the formatted summary string.
pub fn describe_hep_limiters(global: u64, per_peer: u64) -> String {
    let render = |limit: u64| {
        if limit == 0 {
            "disabled".to_string()
        } else {
            format!("{limit}/s")
        }
    };
    format!(
        "HEP rate limiting: global {}, per-peer {}",
        render(global),
        render(per_peer)
    )
}

// ── HMAC authentication mode (opt-in, sipnab↔sipnab) ──────────────────
//
// `HepAuthMode` lives in `crate::cli` (always compiled) so the CLI struct
// can name it without the `hep` feature; the crypto below is HEP-only.

use crate::cli::HepAuthMode;

/// Wire-format version byte of the HMAC auth token.
#[cfg(feature = "hep")]
const HMAC_TOKEN_VERSION: u8 = 1;
/// Token length: version(1) + timestamp(8) + nonce(16) + HMAC-SHA256(32).
#[cfg(feature = "hep")]
const HMAC_TOKEN_LEN: usize = 1 + 8 + 16 + 32;
/// Default acceptance window (seconds) for a token timestamp, each side of
/// `now`.
///
/// Thirty seconds is generous for a pair of hosts running NTP and useless for a
/// pair that are not: on an agent/collector pair with a drifted clock EVERY
/// packet is rejected as out-of-window, and what the operator sees is a
/// collector receiving nothing — a symptom they will attribute to routing, to a
/// firewall, or to a dead agent long before they suspect a clock.
///
/// So the window is settable, with `--hep-hmac-window` or
/// `[security] hep_hmac_window_secs`, and it is capped: widening it is a
/// SECURITY trade, because the window is exactly how long a packet an on-path
/// attacker captured stays acceptable, and it is also how far back the nonce
/// cache must remember. [`crate::config::MAX_HEP_HMAC_WINDOW_SECS`] holds the
/// ceiling and the reasoning for where it sits.
#[cfg(feature = "hep")]
pub const DEFAULT_HMAC_WINDOW_SECS: u64 = 30;

/// Why an HMAC auth token was rejected.
#[cfg(feature = "hep")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAuthError {
    /// Wrong length or unrecognized version byte.
    BadFormat,
    /// Timestamp is further than the acceptance window from now.
    TimestampOutOfWindow,
    /// HMAC did not match (wrong key, or tampered token/payload).
    BadMac,
    /// A token with this nonce was already accepted within the window.
    Replay,
}

/// Compute HMAC-SHA256 of `data` under `key`, returning the 32-byte tag.
/// Pure; on the impossible key-setup failure it returns an all-zero tag,
/// which can never match a real MAC, so verification fails closed.
#[cfg(feature = "hep")]
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    // Local alias: HMAC keyed over SHA-256 (the token's MAC algorithm).
    type HmacSha256 = Hmac<sha2::Sha256>;
    // HMAC accepts a key of any length, so new_from_slice cannot fail; handle
    // the Result without panicking (production forbids unwrap/expect). The
    // impossible Err path returns a zero tag, which fails closed on verify.
    match HmacSha256::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(data);
            let tag = mac.finalize().into_bytes();
            let mut out = [0u8; 32];
            out.copy_from_slice(&tag);
            out
        }
        Err(_) => [0u8; 32],
    }
}

/// The byte region the token's MAC is computed over: version, timestamp,
/// nonce, and the message payload. Binding the payload authenticates the
/// message content, not merely possession of the key.
#[cfg(feature = "hep")]
fn hmac_signed_region(ts: u64, nonce: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 16 + payload.len());
    buf.push(HMAC_TOKEN_VERSION);
    buf.extend_from_slice(&ts.to_be_bytes());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(payload);
    buf
}

/// Build the 57-byte HMAC auth token carried in the `0x000e` chunk when
/// `--hep-auth-mode hmac` is active.
///
/// # Arguments
///
/// * `key` — the shared HMAC secret.
/// * `ts` — token timestamp, seconds since the Unix epoch.
/// * `nonce` — 16-byte unique-per-message nonce.
/// * `payload` — the message bytes the token authenticates.
///
/// # Returns
///
/// The wire token: version(1) + timestamp(8, big-endian) + nonce(16) +
/// HMAC-SHA256 tag(32).
#[cfg(feature = "hep")]
pub fn build_hmac_auth_token(key: &[u8], ts: u64, nonce: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mac = hmac_sha256(key, &hmac_signed_region(ts, nonce, payload));
    let mut token = Vec::with_capacity(HMAC_TOKEN_LEN);
    token.push(HMAC_TOKEN_VERSION);
    token.extend_from_slice(&ts.to_be_bytes());
    token.extend_from_slice(nonce);
    token.extend_from_slice(&mac);
    token
}

/// Verify a received HMAC auth token against the configured key and the
/// message payload, rejecting stale timestamps, bad MACs, and replays.
///
/// The MAC is checked *before* the replay cache is consulted or updated, so
/// a forged token can never seed the cache with an attacker-chosen nonce.
///
/// # Arguments
///
/// * `key` — the shared HMAC secret.
/// * `token` — the received 57-byte wire token.
/// * `payload` — the message bytes the token must authenticate.
/// * `now` — current time, seconds since the Unix epoch.
/// * `window` — acceptance window in seconds, applied on each side of `now`.
/// * `seen` — mutable replay cache of recently accepted nonces.
///
/// # Errors
///
/// `BadFormat` for a wrong length or version byte; `TimestampOutOfWindow`
/// when the token timestamp is more than `window` seconds from `now`;
/// `BadMac` when the HMAC does not match; `Replay` when the nonce was
/// already accepted within the window.
///
/// # Side effects
///
/// On reaching the replay stage, prunes expired entries from `seen` (at most
/// once per second — see `HmacNonceCache::should_prune`), and on success
/// records the token's nonce there.
#[cfg(feature = "hep")]
pub fn verify_hmac_auth_token(
    key: &[u8],
    token: &[u8],
    payload: &[u8],
    now: u64,
    window: u64,
    seen: &mut HmacNonceCache,
) -> Result<(), HmacAuthError> {
    if token.len() != HMAC_TOKEN_LEN || token[0] != HMAC_TOKEN_VERSION {
        return Err(HmacAuthError::BadFormat);
    }
    // Length is exactly HMAC_TOKEN_LEN (checked above), so these fixed-size
    // copies cannot panic and need no unwrap/expect.
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&token[1..9]);
    let ts = u64::from_be_bytes(ts_bytes);
    if now.abs_diff(ts) > window {
        return Err(HmacAuthError::TimestampOutOfWindow);
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&token[9..25]);

    // Verify the MAC before touching the replay cache, so a forged token
    // cannot record its (attacker-chosen) nonce and lock out a legitimate one.
    let expected = hmac_sha256(key, &hmac_signed_region(ts, &nonce, payload));
    if !crate::crypto::constant_time_eq(&expected, &token[25..HMAC_TOKEN_LEN]) {
        return Err(HmacAuthError::BadMac);
    }

    // Amortize the O(n) prune to at most once per second. Correctness does
    // not depend on it: any nonce old enough to prune is also old enough that
    // its token fails the timestamp-window check above, so a lingering stale
    // entry can never be replayed.
    if seen.should_prune(Instant::now()) {
        seen.prune(now.saturating_sub(window));
    }
    if seen.contains(&nonce) {
        return Err(HmacAuthError::Replay);
    }
    seen.insert(nonce, ts);
    Ok(())
}

/// Bounded record of recently accepted token nonces, used to reject replays
/// within the acceptance window. Entries older than the window are pruned,
/// so memory is bounded by the authentic packet rate times the window.
#[cfg(feature = "hep")]
#[derive(Default)]
pub struct HmacNonceCache {
    /// Accepted nonces mapped to their token timestamps (epoch seconds),
    /// used both for replay lookups and for window-based pruning.
    seen: std::collections::HashMap<[u8; 16], u64>,
    /// When the map was last pruned, so the O(n) sweep is amortized to at
    /// most once per second instead of running on every accepted packet.
    /// `None` until the first prune.
    last_prune: Option<Instant>,
}

#[cfg(feature = "hep")]
impl HmacNonceCache {
    /// A fresh, empty replay cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `nonce` was already accepted (and not yet pruned).
    fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.seen.contains_key(nonce)
    }

    /// Record `nonce` as accepted with its token timestamp `ts` (epoch
    /// seconds), mutating the cache.
    fn insert(&mut self, nonce: [u8; 16], ts: u64) {
        self.seen.insert(nonce, ts);
    }

    /// Drop nonces whose timestamp is older than `min_ts`; those can no
    /// longer pass the timestamp check, so they cannot be replayed.
    fn prune(&mut self, min_ts: u64) {
        self.seen.retain(|_, ts| *ts >= min_ts);
    }

    /// Whether a prune is due at monotonic instant `now`. The first call
    /// always returns `true`; afterwards it returns `true` at most once per
    /// second, recording `now` as the last-prune marker each time it does.
    ///
    /// Amortizing is safe because pruning is a memory optimization only: an
    /// expired nonce can never pass the timestamp-window check in
    /// [`verify_hmac_auth_token`], so a not-yet-pruned stale entry cannot be
    /// replayed.
    fn should_prune(&mut self, now: Instant) -> bool {
        match self.last_prune {
            Some(prev) if now.duration_since(prev) < Duration::from_secs(1) => false,
            _ => {
                self.last_prune = Some(now);
                true
            }
        }
    }
}

/// Receiver-side gate for `--hep-auth-mode hmac`. Mirrors [`hep_auth_ok`]'s
/// contract: with no configured secret every packet passes; otherwise the
/// packet must carry a valid, fresh, unreplayed HMAC token over its payload.
///
/// # Arguments
///
/// * `expected` — the configured shared HMAC key, if any.
/// * `token` — the packet's `0x000e` chunk bytes, if present.
/// * `payload` — the packet payload the token must authenticate.
/// * `window_secs` — acceptance window each side of now, from
///   [`HepListenerOpts::hmac_window_secs`].
/// * `cache` — mutable per-listener replay cache.
///
/// # Returns
///
/// `true` when the packet should be accepted, `false` when it must be
/// dropped.
///
/// # Side effects
///
/// Reads the system clock, mutates `cache` (prune/insert) during
/// verification, and logs a `tracing::debug` line on rejection.
#[cfg(feature = "hep")]
fn hmac_auth_ok(
    expected: Option<&str>,
    token: Option<&[u8]>,
    payload: &[u8],
    window_secs: u64,
    cache: &mut HmacNonceCache,
) -> bool {
    match (expected, token) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(key), Some(token)) => {
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            match verify_hmac_auth_token(key.as_bytes(), token, payload, now, window_secs, cache) {
                Ok(()) => true,
                Err(e) => {
                    // A skew rejection drops EVERY packet from that sender and
                    // presents as "the collector receives nothing", which is
                    // the hardest symptom to attribute — the operator suspects
                    // routing, the firewall, the sender's config, and only then
                    // a clock. It logged at debug, so nothing said so at the
                    // default level.
                    //
                    // Warned once per process rather than per packet: a drifted
                    // sender produces this on every datagram, and a line per
                    // packet is its own outage.
                    if e == HmacAuthError::TimestampOutOfWindow {
                        static SKEW_WARNED: std::sync::atomic::AtomicBool =
                            std::sync::atomic::AtomicBool::new(false);
                        if !SKEW_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            tracing::warn!(
                                "HEP HMAC auth is rejecting packets because the \
                                 sender's timestamp is outside the {window_secs}s \
                                 acceptance window — check NTP on the sender, or \
                                 widen it with --hep-hmac-window. Every packet from \
                                 a clock-drifted peer is dropped, so this looks like \
                                 a collector that receives nothing."
                            );
                        }
                    }
                    tracing::debug!("HEP HMAC auth rejected: {e:?}");
                    false
                }
            }
        }
    }
}

// ── Public types ─────────────────────────────────────────────────────

/// Protocol type carried inside a HEP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HepProtocol {
    /// SIP signaling (protocol type 1).
    Sip,
    /// RTCP control packets (protocol type 5).
    Rtcp,
    /// RTP media packets (protocol type 32).
    Rtp,
    /// Unrecognized protocol type.
    Unknown(u8),
}

impl HepProtocol {
    /// Decode a HEP protocol type byte into the enum.
    fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Sip,
            5 => Self::Rtcp,
            32 => Self::Rtp,
            other => Self::Unknown(other),
        }
    }

    /// Encode the enum back to a HEP protocol type byte.
    fn to_byte(self) -> u8 {
        match self {
            Self::Sip => 1,
            Self::Rtcp => 5,
            Self::Rtp => 32,
            Self::Unknown(b) => b,
        }
    }
}

/// A parsed HEP packet with extracted metadata and payload.
#[derive(Debug, Clone)]
pub struct HepPacket {
    /// HEP version (2 or 3).
    pub version: u8,
    /// Source IP address from the original SIP/RTP flow.
    pub src_addr: IpAddr,
    /// Destination IP address from the original SIP/RTP flow.
    pub dst_addr: IpAddr,
    /// Source transport port.
    pub src_port: u16,
    /// Destination transport port.
    pub dst_port: u16,
    /// Timestamp of the captured packet.
    pub timestamp: DateTime<Utc>,
    /// Application protocol type (SIP, RTP, RTCP, etc.) — from the HEP
    /// `CHUNK_PROTO_TYPE` chunk. Distinct from `ip_protocol` below.
    pub protocol: HepProtocol,
    /// IANA IP protocol number (17 = UDP, 6 = TCP, 132 = SCTP) — from
    /// the HEP `CHUNK_IP_PROTO` chunk. Defaults to UDP when the chunk
    /// is absent (the common case for SIP/RTP HEP traffic).
    pub ip_protocol: u8,
    /// The encapsulated payload (SIP message, RTP packet, etc.).
    pub payload: Vec<u8>,
    /// Correlation ID (typically Call-ID), if present (v3 only).
    pub correlation_id: Option<String>,
    /// Capture agent ID, if present (v3 only).
    pub capture_id: Option<u32>,
    /// Authenticate-key / shared secret from the HEP `0x000e` chunk, if
    /// present (v3 only). Retained so the receiver can authenticate the
    /// sender; compared in constant time via [`hep_auth_ok`].
    pub auth_key: Option<Vec<u8>>,
}

// ── Parsing ──────────────────────────────────────────────────────────

/// Parse a HEP packet from raw bytes.
///
/// Detects the version automatically:
/// - First 4 bytes == `"HEP3"` → HEP v3 (chunk-based)
/// - First byte == `0x02` → HEP v2 (fixed header)
///
/// # Errors
///
/// Returns an error if the packet is malformed, truncated, or
/// uses an unrecognized version.
pub fn parse_hep(data: &[u8]) -> Result<HepPacket> {
    if data.len() >= 4 && &data[..4] == HEP3_MAGIC {
        parse_hep_v3(data)
    } else if !data.is_empty() && data[0] == HEP2_VERSION {
        parse_hep_v2(data)
    } else {
        bail!("Not a HEP packet: unrecognized magic/version byte");
    }
}

/// Parse a HEP v3 (chunk-based) packet.
///
/// Walks the chunk list after the 6-byte `"HEP3"` + total-length header,
/// collecting addresses, ports, timestamp, protocol, payload, and optional
/// correlation/capture/auth chunks. Unknown chunk types are skipped (with a
/// `tracing::trace` line) for forward compatibility. An out-of-range
/// `TS_USEC` is clamped rather than rejected, and an unrepresentable
/// timestamp falls back to the current time.
///
/// # Arguments
///
/// * `data` — the full received datagram, starting at the `"HEP3"` magic.
///
/// # Returns
///
/// The extracted `HepPacket` with `version = 3`.
///
/// # Errors
///
/// Returns an error when the packet or any chunk is truncated, a chunk's
/// declared length is smaller than its 6-byte header or overflows the
/// packet, or a required source/destination address chunk is missing.
fn parse_hep_v3(data: &[u8]) -> Result<HepPacket> {
    ensure!(
        data.len() >= HEP3_HEADER_LEN,
        "HEP v3 packet too short: {} bytes (minimum {})",
        data.len(),
        HEP3_HEADER_LEN,
    );

    let total_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    ensure!(
        total_len <= data.len(),
        "HEP v3 total_length ({total_len}) exceeds packet size ({})",
        data.len(),
    );

    // Walk chunks
    let mut src_addr: Option<IpAddr> = None;
    let mut dst_addr: Option<IpAddr> = None;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut ts_sec: u32 = 0;
    let mut ts_usec: u32 = 0;
    let mut protocol = HepProtocol::Unknown(0);
    let mut ip_protocol: u8 = 17; // Default to UDP — most HEP traffic is SIP/UDP or RTP/UDP.
    let mut payload: Vec<u8> = Vec::new();
    let mut correlation_id: Option<String> = None;
    let mut capture_id: Option<u32> = None;
    let mut auth_key: Option<Vec<u8>> = None;

    let mut offset = HEP3_HEADER_LEN;
    while offset + CHUNK_HEADER_LEN <= total_len {
        let _vendor = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let chunk_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let chunk_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as usize;

        ensure!(
            chunk_len >= CHUNK_HEADER_LEN,
            "HEP v3 chunk length ({chunk_len}) is smaller than header ({})",
            CHUNK_HEADER_LEN,
        );
        ensure!(
            offset + chunk_len <= total_len,
            "HEP v3 chunk at offset {offset} overflows packet (chunk_len={chunk_len}, remaining={})",
            total_len - offset,
        );

        let chunk_data = &data[offset + CHUNK_HEADER_LEN..offset + chunk_len];

        match chunk_type {
            CHUNK_IP_FAMILY => {
                // 1 byte: 2=IPv4, 10=IPv6 — informational, addresses come
                // from dedicated chunks.
            }
            CHUNK_IP_PROTO => {
                ensure!(!chunk_data.is_empty(), "IP_PROTO chunk too short");
                ip_protocol = chunk_data[0];
            }
            CHUNK_SRC_IPV4 => {
                ensure!(chunk_data.len() >= 4, "SRC_IPV4 chunk too short");
                src_addr = Some(IpAddr::V4(Ipv4Addr::new(
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                )));
            }
            CHUNK_DST_IPV4 => {
                ensure!(chunk_data.len() >= 4, "DST_IPV4 chunk too short");
                dst_addr = Some(IpAddr::V4(Ipv4Addr::new(
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                )));
            }
            CHUNK_SRC_IPV6 => {
                ensure!(chunk_data.len() >= 16, "SRC_IPV6 chunk too short");
                let octets: [u8; 16] =
                    chunk_data[..16].try_into().context("SRC_IPV6 conversion")?;
                src_addr = Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            CHUNK_DST_IPV6 => {
                ensure!(chunk_data.len() >= 16, "DST_IPV6 chunk too short");
                let octets: [u8; 16] =
                    chunk_data[..16].try_into().context("DST_IPV6 conversion")?;
                dst_addr = Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            CHUNK_SRC_PORT => {
                ensure!(chunk_data.len() >= 2, "SRC_PORT chunk too short");
                src_port = u16::from_be_bytes([chunk_data[0], chunk_data[1]]);
            }
            CHUNK_DST_PORT => {
                ensure!(chunk_data.len() >= 2, "DST_PORT chunk too short");
                dst_port = u16::from_be_bytes([chunk_data[0], chunk_data[1]]);
            }
            CHUNK_TS_SEC => {
                ensure!(chunk_data.len() >= 4, "TS_SEC chunk too short");
                ts_sec = u32::from_be_bytes([
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                ]);
            }
            CHUNK_TS_USEC => {
                ensure!(chunk_data.len() >= 4, "TS_USEC chunk too short");
                ts_usec = u32::from_be_bytes([
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                ]);
            }
            CHUNK_PROTO_TYPE => {
                ensure!(!chunk_data.is_empty(), "PROTO_TYPE chunk too short");
                protocol = HepProtocol::from_byte(chunk_data[0]);
            }
            CHUNK_CAPTURE_ID => {
                ensure!(chunk_data.len() >= 4, "CAPTURE_ID chunk too short");
                capture_id = Some(u32::from_be_bytes([
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                ]));
            }
            CHUNK_AUTH_KEY => {
                auth_key = Some(chunk_data.to_vec());
            }
            CHUNK_PAYLOAD => {
                payload = chunk_data.to_vec();
            }
            CHUNK_CORRELATION_ID => {
                correlation_id = Some(
                    String::from_utf8_lossy(chunk_data)
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            _ => {
                // Unknown chunk — skip silently for forward compatibility.
                tracing::trace!(
                    "Skipping unknown HEP v3 chunk: vendor={_vendor:#06x}, type={chunk_type:#06x}"
                );
            }
        }

        offset += chunk_len;
    }

    // `ts_usec` is attacker-controlled; widen and clamp before the µs→ns
    // conversion so it can't overflow u32 (panic in debug / wrap in release).
    let nanos = (ts_usec as u64 * 1000).min(999_999_999) as u32;
    let timestamp = Utc
        .timestamp_opt(ts_sec as i64, nanos)
        .single()
        .unwrap_or_else(Utc::now);

    Ok(HepPacket {
        version: 3,
        src_addr: src_addr.context("HEP v3 packet missing source address chunk")?,
        dst_addr: dst_addr.context("HEP v3 packet missing destination address chunk")?,
        src_port,
        dst_port,
        timestamp,
        protocol,
        ip_protocol,
        payload,
        correlation_id,
        capture_id,
        auth_key,
    })
}

/// Parse a HEP v2 (fixed-header) packet.
///
/// Reads the fixed IPv4-only header (ports at bytes 2..6, addresses at
/// 6..14) and treats everything past the declared header length as payload.
/// HEP v2 carries no timestamp, so the packet is stamped with the current
/// time; protocol is always SIP over UDP and there is no auth-key field.
///
/// # Arguments
///
/// * `data` — the full received datagram, starting at the 0x02 version byte.
///
/// # Returns
///
/// The extracted `HepPacket` with `version = 2`.
///
/// # Errors
///
/// Returns an error when the packet is too short to hold its declared
/// header, or the declared header length is below the 16-byte minimum.
fn parse_hep_v2(data: &[u8]) -> Result<HepPacket> {
    ensure!(
        data.len() >= 2,
        "HEP v2 packet too short to read header length",
    );

    let header_len = data[1] as usize;
    ensure!(
        header_len >= HEP2_MIN_HEADER,
        "HEP v2 header length ({header_len}) is below minimum ({HEP2_MIN_HEADER})",
    );
    ensure!(
        data.len() >= header_len,
        "HEP v2 packet truncated: have {} bytes, header says {header_len}",
        data.len(),
    );

    // Fixed layout after version + header_len:
    //   [2..4]  source port
    //   [4..6]  dest port
    //   [6..10] source IPv4
    //   [10..14] dest IPv4
    let src_port = u16::from_be_bytes([data[2], data[3]]);
    let dst_port = u16::from_be_bytes([data[4], data[5]]);
    let src_addr = IpAddr::V4(Ipv4Addr::new(data[6], data[7], data[8], data[9]));
    let dst_addr = IpAddr::V4(Ipv4Addr::new(data[10], data[11], data[12], data[13]));

    let payload = data[header_len..].to_vec();

    Ok(HepPacket {
        version: 2,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        timestamp: Utc::now(),
        protocol: HepProtocol::Sip, // v2 was SIP-only
        ip_protocol: 17,            // v2 carried only UDP-borne SIP
        payload,
        correlation_id: None,
        capture_id: None,
        // HEP v2's fixed header has no auth-key field; receiver-side
        // authentication therefore applies to v3 senders only.
        auth_key: None,
    })
}

// ── HEP v3 builder (for sender) ─────────────────────────────────────

/// Network endpoint pair for HEP packet construction.
pub struct HepEndpoint {
    /// Source IP address of the original packet.
    pub src_addr: IpAddr,
    /// Destination IP address of the original packet.
    pub dst_addr: IpAddr,
    /// Source transport port.
    pub src_port: u16,
    /// Destination transport port.
    pub dst_port: u16,
    /// Transport the original packet rode on.
    ///
    /// The fifth element of the 5-tuple this struct already models, and the
    /// value HEP's `IP protocol` chunk carries. It was not a field: the chunk
    /// was written as a literal 17, so SIP captured over TCP — and SIP
    /// recovered from TLS, which the pipeline goes out of its way to stamp as
    /// [`TransportProto::Tls`] "so the pipeline parses (and reports) the true
    /// transport origin" — both reached the collector labeled UDP.
    pub transport: TransportProto,
}

impl HepEndpoint {
    /// The IANA IP protocol number for this endpoint's transport.
    ///
    /// TLS and WebSocket report 6: the chunk answers "what was on the wire",
    /// and both ride TCP, so a collector filtering `proto=tcp` must find them.
    fn ip_protocol(&self) -> u8 {
        match self.transport {
            TransportProto::Udp => 17,
            TransportProto::Tcp | TransportProto::Tls | TransportProto::Ws => 6,
            TransportProto::Sctp => 132,
        }
    }
}

/// Build a HEP v3 packet from components.
///
/// Constructs a valid HEP v3 byte sequence with all required chunks.
/// Used by [`HepSender`] and by round-trip tests.
///
/// # Arguments
///
/// * `endpoint` — source/destination addresses and ports of the original flow.
/// * `timestamp` — capture time, encoded as TS_SEC/TS_USEC chunks.
/// * `protocol` — application protocol type chunk (SIP/RTCP/RTP/...).
/// * `capture_id` — capture agent ID chunk value.
/// * `auth_key` — optional Homer shared secret, emitted verbatim as the
///   `0x000e` chunk when `Some`.
/// * `payload` — the encapsulated message bytes.
///
/// # Returns
///
/// The complete wire-format HEP v3 packet bytes.
pub fn build_hep_v3(
    endpoint: &HepEndpoint,
    timestamp: DateTime<Utc>,
    protocol: HepProtocol,
    capture_id: u32,
    auth_key: Option<&str>,
    payload: &[u8],
) -> Vec<u8> {
    build_hep_v3_bytes(
        endpoint,
        timestamp,
        protocol,
        capture_id,
        auth_key.map(str::as_bytes),
        payload,
    )
}

/// Like [`build_hep_v3`] but the `0x000e` auth chunk carries arbitrary
/// bytes, so `--hep-auth-mode hmac` can stamp a binary token there instead
/// of a cleartext key.
///
/// Same arguments and return value as `build_hep_v3`, except `auth_key`
/// is raw bytes (e.g. a binary HMAC token) rather than a UTF-8 secret.
pub fn build_hep_v3_bytes(
    endpoint: &HepEndpoint,
    timestamp: DateTime<Utc>,
    protocol: HepProtocol,
    capture_id: u32,
    auth_key: Option<&[u8]>,
    payload: &[u8],
) -> Vec<u8> {
    let src_addr = endpoint.src_addr;
    let dst_addr = endpoint.dst_addr;
    let src_port = endpoint.src_port;
    let dst_port = endpoint.dst_port;
    let mut chunks: Vec<u8> = Vec::with_capacity(256 + payload.len());

    // IP protocol family
    let family: u8 = match src_addr {
        IpAddr::V4(_) => 2,
        IpAddr::V6(_) => 10,
    };
    append_chunk(&mut chunks, 0x0000, CHUNK_IP_FAMILY, &[family]);

    // IP protocol, from the transport actually observed — not a literal 17.
    // The address family two chunks up was already derived from the address;
    // this one was pinned, so every TCP and TLS capture was forwarded as UDP.
    append_chunk(
        &mut chunks,
        0x0000,
        CHUNK_IP_PROTO,
        &[endpoint.ip_protocol()],
    );

    // Source/destination addresses
    match src_addr {
        IpAddr::V4(v4) => {
            append_chunk(&mut chunks, 0x0000, CHUNK_SRC_IPV4, &v4.octets());
        }
        IpAddr::V6(v6) => {
            append_chunk(&mut chunks, 0x0000, CHUNK_SRC_IPV6, &v6.octets());
        }
    }
    match dst_addr {
        IpAddr::V4(v4) => {
            append_chunk(&mut chunks, 0x0000, CHUNK_DST_IPV4, &v4.octets());
        }
        IpAddr::V6(v6) => {
            append_chunk(&mut chunks, 0x0000, CHUNK_DST_IPV6, &v6.octets());
        }
    }

    // Ports
    append_chunk(&mut chunks, 0x0000, CHUNK_SRC_PORT, &src_port.to_be_bytes());
    append_chunk(&mut chunks, 0x0000, CHUNK_DST_PORT, &dst_port.to_be_bytes());

    // Timestamp. The HEP TS_SEC chunk is a fixed 32-bit seconds-since-epoch
    // field on the wire, so capture times before 1970-01-01 or after
    // 2106-02-07 06:28:15 UTC cannot be represented. Clamp into the u32 range
    // rather than let `as u32` silently truncate a post-2106 time or wrap a
    // pre-1970 one into a bogus far-future value, and log once (not per
    // packet) so the wire-format constraint is visible without flooding logs.
    let ts_raw = timestamp.timestamp();
    let ts_sec = ts_raw.clamp(0, u32::MAX as i64) as u32;
    if ts_raw != i64::from(ts_sec) {
        static TS_CLAMP_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if !TS_CLAMP_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::debug!(
                "HEP TS_SEC is a fixed u32 seconds field; capture time {ts_raw}s is outside \
                 1970-01-01..2106-02-07 and was clamped to {ts_sec}s (logged once)"
            );
        }
    }
    let ts_usec = timestamp.timestamp_subsec_micros();
    append_chunk(&mut chunks, 0x0000, CHUNK_TS_SEC, &ts_sec.to_be_bytes());
    append_chunk(&mut chunks, 0x0000, CHUNK_TS_USEC, &ts_usec.to_be_bytes());

    // Protocol type
    append_chunk(&mut chunks, 0x0000, CHUNK_PROTO_TYPE, &[protocol.to_byte()]);

    // Capture agent ID
    append_chunk(
        &mut chunks,
        0x0000,
        CHUNK_CAPTURE_ID,
        &capture_id.to_be_bytes(),
    );

    // Authenticate key (Homer shared secret) or HMAC token, when configured.
    if let Some(key) = auth_key {
        append_chunk(&mut chunks, 0x0000, CHUNK_AUTH_KEY, key);
    }

    // Payload. HEP3 length fields (both the per-chunk length and the total)
    // are u16, so the whole packet must fit in 65535 bytes. Truncate an
    // oversized payload to what remains rather than emit a wrapped, corrupt
    // length that the receiver would misframe. (HMAC auth over a truncated
    // payload will fail verification on the receiver, which is the safe
    // outcome — a dropped packet, not a mis-parsed one.)
    let fixed = HEP3_HEADER_LEN + chunks.len() + CHUNK_HEADER_LEN;
    let max_payload = (u16::MAX as usize).saturating_sub(fixed);
    let payload = if payload.len() > max_payload {
        &payload[..max_payload]
    } else {
        payload
    };
    append_chunk(&mut chunks, 0x0000, CHUNK_PAYLOAD, payload);

    // Build final packet: magic + total_length + chunks. total now fits u16.
    let total_len = (HEP3_HEADER_LEN + chunks.len()) as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.extend_from_slice(HEP3_MAGIC);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&chunks);
    pkt
}

/// Append a single HEP v3 chunk to `buf`: a 6-byte header (`vendor`,
/// `chunk_type`, and a length that includes the header) followed by `data`
/// verbatim. All header fields are big-endian. Mutates `buf` in place.
fn append_chunk(buf: &mut Vec<u8>, vendor: u16, chunk_type: u16, data: &[u8]) {
    let len = (CHUNK_HEADER_LEN + data.len()) as u16;
    buf.extend_from_slice(&vendor.to_be_bytes());
    buf.extend_from_slice(&chunk_type.to_be_bytes());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

// ── CIDR allowlist ──────────────────────────────────────────────────

/// A parsed CIDR range for IP allowlisting.
#[derive(Debug, Clone)]
pub struct CidrRange {
    /// Network address (masked).
    network: u128,
    /// Number of prefix bits.
    prefix_len: u8,
    /// Whether this is an IPv4 or IPv6 range.
    is_v4: bool,
}

impl CidrRange {
    /// Parse a CIDR string like "10.0.0.0/8" or "2001:db8::/32".
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidCidr`] if the notation is invalid.
    pub fn parse(cidr: &str) -> Result<Self, crate::Error> {
        Self::parse_inner(cidr).map_err(|reason| crate::Error::InvalidCidr {
            input: cidr.to_string(),
            reason,
        })
    }

    /// Parse implementation: split `cidr` at `/`, parse the address and
    /// prefix length, and normalize to a masked 128-bit network value
    /// (IPv4 occupies the top 32 bits). Returns the range or a plain-text
    /// reason string for `CidrRange::parse` to wrap.
    fn parse_inner(cidr: &str) -> Result<Self, String> {
        // A bare address is a HOST, so `--hep-allow 10.0.0.40` means what an
        // operator plainly intends without their having to know to write
        // `/32`. Note which way this defaults: a host route is the NARROWEST
        // reading, so a missing prefix can only ever admit less. Inferring a
        // classful network from `10.0.0.0` would silently admit sixteen
        // million addresses nobody named, which is the opposite of what an
        // allowlist is for.
        let (addr_str, prefix_str) = match cidr.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (cidr, None),
        };

        let addr: IpAddr = addr_str.parse().map_err(|e| format!("invalid IP: {e}"))?;

        let (ip_bits, is_v4, max_prefix) = match addr {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4) as u128;
                (bits << 96, true, 32u8)
            }
            IpAddr::V6(v6) => (u128::from(v6), false, 128u8),
        };

        let prefix_len: u8 = match prefix_str {
            Some(p) => p
                .parse()
                .map_err(|e| format!("invalid prefix length: {e}"))?,
            // Full width for the family: one host, and only that host.
            None => max_prefix,
        };

        if prefix_len > max_prefix {
            return Err(format!(
                "prefix length {prefix_len} exceeds maximum {max_prefix} for '{cidr}'"
            ));
        }

        let mask = if prefix_len == 0 {
            0u128
        } else if is_v4 {
            let shift = 32 - prefix_len;
            ((u32::MAX << shift) as u128) << 96
        } else {
            u128::MAX << (128 - prefix_len)
        };

        Ok(Self {
            network: ip_bits & mask,
            prefix_len,
            is_v4,
        })
    }

    /// Check whether an IP address falls within this CIDR range.
    /// Returns `false` for an address-family mismatch (an IPv4 range never
    /// contains an IPv6 address, and vice versa).
    pub fn contains(&self, addr: IpAddr) -> bool {
        let ip_bits = match addr {
            IpAddr::V4(v4) => {
                if !self.is_v4 {
                    return false;
                }
                (u32::from(v4) as u128) << 96
            }
            IpAddr::V6(v6) => {
                if self.is_v4 {
                    return false;
                }
                u128::from(v6)
            }
        };

        let max_prefix = if self.is_v4 { 32u8 } else { 128u8 };
        let mask = if self.prefix_len == 0 {
            0u128
        } else if self.is_v4 {
            let shift = 32 - self.prefix_len;
            ((u32::MAX << shift) as u128) << 96
        } else {
            u128::MAX << (max_prefix - self.prefix_len)
        };

        (ip_bits & mask) == self.network
    }
}

/// Fixed-window rate limiter for HEP input, with both a global ceiling and a
/// per-peer cap.
///
/// The counting is [`crate::rate_limit::FixedWindowLimiter`], shared with the
/// MCP server's per-peer call limit rather than written twice: the memory
/// bound on tracked peers, the window reset and the "0 disables this half"
/// convention are one implementation, and a fix to any of them reaches both
/// surfaces. What stays here is the part that is genuinely HEP's — the wording
/// of the drop lines an operator greps for, and the `bool` the receive loop
/// wants instead of a reason it has nothing to do with.
struct HepRateLimiter {
    /// Global-ceiling and per-peer counting, keyed by source address.
    inner: crate::rate_limit::FixedWindowLimiter<IpAddr>,
}

impl HepRateLimiter {
    /// `global_max` caps total packets/second across all peers; `per_peer_max`
    /// caps packets/second from any single source IP. A zero value disables
    /// the corresponding limiter: `per_peer_max == 0` leaves only the global
    /// ceiling, and `global_max == 0` leaves only the per-peer cap (or no
    /// limiting at all when both are 0). `max_tracked_peers` bounds how many
    /// distinct source IPs one window may hold.
    fn new(global_max: u64, per_peer_max: u64, max_tracked_peers: usize) -> Self {
        Self {
            inner: crate::rate_limit::FixedWindowLimiter::new(
                global_max,
                per_peer_max,
                max_tracked_peers,
            ),
        }
    }

    /// Returns `true` if a packet from `peer` may be processed, `false` if it
    /// is rate-limited by either the global ceiling or the per-peer cap.
    ///
    /// # Side effects
    ///
    /// Reads the monotonic clock; counts the packet; and on a drop, logs a
    /// `tracing::debug` line naming which bound refused it and the running
    /// total.
    fn allow(&mut self, peer: IpAddr) -> bool {
        use crate::rate_limit::Refusal;
        let Err(refusal) = self.inner.check(peer, Instant::now()) else {
            return true;
        };
        let dropped = self.inner.refused_total();
        match refusal {
            // TrackingFull refuses a LEGITIMATE peer — one inside every rate
            // budget, turned away because the tracking table is full. It is not
            // the same event as exceeding a limit you set, and `--hep-rate-limit`
            // cannot relieve it, because that bounds rate and this bounds
            // capacity. A collector fronting a large fleet hits it and sees
            // nothing at the default log level.
            //
            // Warned once: the condition persists for the whole window and a
            // line per refused packet would bury the one that matters.
            Refusal::TrackingFull => {
                static FULL_WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !FULL_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::warn!(
                        "HEP peer tracking is full at {} distinct peers in one second, \
                         so packets from NEW peers are being dropped even though they \
                         are inside every rate limit. --hep-rate-limit does not help: \
                         it bounds rate, this bounds how many peers can be tracked at \
                         once — raise [limits] max_tracked_peers. First refused peer: \
                         {peer}.",
                        self.inner.max_tracked_peers()
                    );
                }
                tracing::debug!(
                    "HEP per-peer tracking full ({} peers); dropping new peer {peer} (total dropped: {dropped})",
                    self.inner.max_tracked_peers()
                );
            }
            Refusal::PerPeer => tracing::debug!(
                "HEP per-peer rate limit exceeded ({}/s) for {peer}, dropping (total dropped: {dropped})",
                self.inner.per_peer_max()
            ),
            Refusal::Global => tracing::debug!(
                "HEP global rate limit exceeded ({}/s), dropping packet (total dropped: {dropped})",
                self.inner.global_max()
            ),
        }
        false
    }
}

// ── HEP capture (receiver) ──────────────────────────────────────────

/// How long the HEP listener may go without receiving a packet before
/// it warns the operator. UDP is connectionless: a dead upstream sender
/// produces no error, just silence — without this, a stalled feed is
/// indistinguishable from a quiet one.
pub const HEP_IDLE_WARN_AFTER: Duration = Duration::from_secs(30);

/// Detects silent stalls in a packet feed.
///
/// Pure state machine over caller-supplied [`Instant`]s so it is testable
/// without sleeping: [`IdleWatch::check`] returns `Some(idle)` exactly once
/// per idle period when the threshold is crossed, and
/// [`IdleWatch::on_packet`] returns `Some(outage)` on the first packet
/// after a warned period. A zero threshold disables the watch.
pub struct IdleWatch {
    /// Idle duration that triggers a warning (zero disables the watch).
    threshold: Duration,
    /// When the last packet was observed (or when the watch was created).
    last_packet: Instant,
    /// Whether the current idle period has already been warned about.
    warned: bool,
}

impl IdleWatch {
    /// Create a watch; `now` starts the first idle period.
    pub fn new(threshold: Duration, now: Instant) -> Self {
        Self {
            threshold,
            last_packet: now,
            warned: false,
        }
    }

    /// Record traffic at time `now`. Returns `Some(outage_duration)` if this
    /// packet ends a previously-warned idle period (i.e., the feed
    /// recovered), else `None`. Mutates the watch: resets the idle clock and
    /// clears the warned flag.
    pub fn on_packet(&mut self, now: Instant) -> Option<Duration> {
        let idle = now.duration_since(self.last_packet);
        self.last_packet = now;
        if std::mem::take(&mut self.warned) {
            Some(idle)
        } else {
            None
        }
    }

    /// Poll the watch at time `now`. Returns `Some(idle_duration)` the first
    /// time the idle threshold is crossed; `None` on subsequent polls until
    /// traffic resumes (no log spam). Mutates the watch: sets the warned
    /// flag when the threshold is crossed.
    pub fn check(&mut self, now: Instant) -> Option<Duration> {
        if self.threshold.is_zero() || self.warned {
            return None;
        }
        let idle = now.duration_since(self.last_packet);
        if idle >= self.threshold {
            self.warned = true;
            Some(idle)
        } else {
            None
        }
    }
}

/// Whether a `recv_from` error is transient (retry) rather than fatal. The
/// read-timeout poll makes `WouldBlock`/`TimedOut` routine, and a signal can
/// interrupt the blocking call (`Interrupted`/EINTR) at any time — none of these
/// mean the socket is broken, so the listener must retry, not die.
fn is_transient_recv_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

/// Options for the HEP listener, grouped so [`capture_hep`] keeps a small
/// signature. Borrows the allowlist and secret from the caller.
pub struct HepListenerOpts<'a> {
    /// CIDR allowlist for the outer UDP source (empty = allow any source).
    pub allowlist: &'a [CidrRange],
    /// Global ceiling: maximum HEP packets/second across all peers.
    pub rate_limit: u64,
    /// Per-peer cap: maximum HEP packets/second from any one source IP
    /// (0 = disabled; the global ceiling still applies).
    pub per_peer_rate_limit: u64,
    /// Distinct source IPs one counting window may hold at once
    /// (`[limits] max_tracked_peers`). Past it a source sipnab has not
    /// already seen this second is refused.
    pub max_tracked_peers: usize,
    /// Receiver-side shared secret. When `Some`, incoming packets must carry
    /// a matching 0x000e auth-key chunk (constant-time compared) or be dropped.
    pub auth_key: Option<&'a str>,
    /// How the 0x000e chunk is interpreted: a verbatim shared secret
    /// (`Plain`) or a per-message HMAC token (`Hmac`).
    pub auth_mode: HepAuthMode,
    /// Seconds either side of now a `Hmac` token's timestamp may fall
    /// (`[security] hep_hmac_window_secs`). Ignored in `Plain` mode, which
    /// carries no timestamp at all.
    pub hmac_window_secs: u64,
}

/// HEP listener: binds a UDP socket and receives HEP packets.
///
/// Each received HEP packet is parsed and converted via `hep_to_packet`
/// into a [`Packet`] carrying `pre_parsed` metadata (src/dst addr+port and
/// IP protocol). The parser short-circuits on `pre_parsed`, treating the
/// HEP payload as the transport-layer message bytes directly.
///
/// The listener checks [`signals::shutdown_requested`] each iteration and
/// respects the `count` and `duration` limits from `config`. Source
/// filtering, rate limiting, and receiver-side authentication come from
/// [`HepListenerOpts`].
///
/// # Default bind address
///
/// Per design decision D18, the default bind address is `127.0.0.1:9060`.
/// A non-loopback bind is refused unless `opts.auth_key` or a non-empty
/// `opts.allowlist` is configured (SN-01).
///
/// # Arguments
///
/// * `bind_addr` — UDP address to bind (host:port; port 0 = ephemeral).
/// * `config` — capture limits (`count` = max packets *received*, counted
///   before allowlist/rate-limit/auth drops; `duration` = max runtime);
///   either being reached stops the listener cleanly.
/// * `tx` — pipeline channel each converted `Packet` is sent to; the loop
///   ends when the receiving side is dropped.
/// * `opts` — allowlist, rate limits, and receiver-side auth settings.
/// * `ready_tx` — optional one-shot channel that receives `Ok(())` once the
///   socket is bound (or `Err(reason)` on startup failure), letting the
///   spawning thread await readiness.
///
/// # Returns
///
/// `Ok(())` after a clean stop (shutdown signal, count/duration limit, or
/// receiver dropped).
///
/// # Errors
///
/// Returns an error if the bind policy is violated, the UDP socket cannot
/// be bound or configured, or a non-transient socket receive error occurs.
///
/// # Side effects
///
/// Binds and reads a UDP socket (blocking, with a 100 ms read timeout);
/// logs startup/limit/drop/idle events via `tracing`; sends readiness on
/// `ready_tx`; forwards accepted packets to `tx` (blocking on channel
/// backpressure); and maintains internal rate-limiter and HMAC replay-cache
/// state for the life of the loop.
pub fn capture_hep(
    bind_addr: &str,
    config: &CaptureConfig,
    tx: PacketTx,
    opts: &HepListenerOpts<'_>,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<()> {
    let HepListenerOpts {
        allowlist,
        rate_limit,
        per_peer_rate_limit,
        max_tracked_peers,
        auth_key,
        auth_mode,
        hmac_window_secs,
    } = *opts;

    // Fail closed on an unguarded non-loopback bind before touching the
    // socket (SN-01, D18): a routable HEP listener must be constrained by a
    // shared secret or a source allowlist.
    if let Err(reason) = enforce_hep_bind_policy(bind_addr, auth_key.is_some(), allowlist.len()) {
        if let Some(ready) = ready_tx {
            let _ = ready.send(Err(reason.clone()));
        }
        return Err(anyhow::anyhow!(reason));
    }

    let socket = match UdpSocket::bind(bind_addr)
        .with_context(|| format!("Failed to bind HEP listener on '{bind_addr}'"))
    {
        Ok(s) => s,
        Err(e) => {
            if let Some(ready) = ready_tx {
                let _ = ready.send(Err(format!("{e:#}")));
            }
            return Err(e);
        }
    };

    // 100ms timeout so we can check shutdown_requested() frequently
    if let Err(e) = socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("Failed to set socket read timeout")
    {
        if let Some(ready) = ready_tx {
            let _ = ready.send(Err(format!("{e:#}")));
        }
        return Err(e);
    }

    // Signal that the HEP socket is bound and ready.
    if let Some(ready) = ready_tx {
        let _ = ready.send(Ok(()));
    }

    let start = Instant::now();
    let mut count: u64 = 0;
    let mut buf = vec![0u8; 65535];
    let mut rate_limiter = HepRateLimiter::new(rate_limit, per_peer_rate_limit, max_tracked_peers);
    // Per-SENDER frame numbering. Bounded by the same figure as the rate
    // limiter's peer table, and for the same reason: the label is built from a
    // capture-agent id an unauthenticated peer chooses.
    let mut frames = HepFrameOrdinals::new(max_tracked_peers);
    // Per-listener replay cache for HMAC auth mode (SN-01 residual).
    let mut hmac_nonce_cache = HmacNonceCache::new();

    if !allowlist.is_empty() {
        tracing::info!("HEP allowlist active: {} CIDR range(s)", allowlist.len());
    }
    tracing::info!("{}", describe_hep_limiters(rate_limit, per_peer_rate_limit));
    // Loopback classification is purely syntactic (no DNS in a security
    // check), so a hostname bind cannot be verified as loopback and is
    // treated as routable. enforce_hep_bind_policy already fail-closes it
    // when no auth or allowlist is set; when it is allowed, warn and suggest a
    // literal so the operator knows the loopback shortcut did not apply.
    if !hep_bind_is_ip_literal(bind_addr) {
        tracing::warn!(
            "HEP listen address '{bind_addr}' is not a literal IP; sipnab does not resolve \
             it to decide loopback vs routable (a DNS lookup in a security check could block \
             or be spoofed) and treats it as non-loopback. Use a literal such as \
             127.0.0.1:PORT or 0.0.0.0:PORT."
        );
    }
    if auth_key.is_some() {
        tracing::info!("HEP receiver authentication active: packets must carry a matching key");
    } else if !hep_bind_is_loopback(bind_addr) {
        tracing::warn!(
            "HEP listener on {bind_addr} is non-loopback and unauthenticated — the inner \
             src/dst addresses a sender asserts are trusted verbatim; prefer --hep-auth."
        );
    }

    // Log the actual bound address: with port 0 the OS assigns an ephemeral
    // port, so logging `bind_addr` would print ":0" (mirrors the REST API).
    let actual_addr = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind_addr.to_string());
    tracing::info!("HEP listener started on {actual_addr}");

    let mut idle_watch = IdleWatch::new(HEP_IDLE_WARN_AFTER, Instant::now());

    loop {
        if signals::shutdown_requested() {
            tracing::debug!("Shutdown requested, stopping HEP listener");
            break;
        }

        if let Some(max_count) = config.count
            && count >= max_count
        {
            tracing::debug!("Reached packet count limit ({max_count})");
            break;
        }

        if let Some(duration) = config.duration
            && start.elapsed() >= duration
        {
            tracing::debug!("Reached duration limit ({duration:?})");
            break;
        }

        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok((n, peer)) => (n, peer),
            // EINTR: a signal interrupted the blocking recv — retry immediately,
            // silently. Treating it as fatal let a single stray signal kill the
            // listener (the read-timeout poll makes EINTR routine here).
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(ref e) if is_transient_recv_error(e.kind()) => {
                if let Some(idle) = idle_watch.check(Instant::now()) {
                    tracing::warn!(
                        "HEP listener on {bind_addr}: no packets for {}s — \
                         upstream sender may be down (UDP gives no error for \
                         a dead peer); capture is still listening",
                        idle.as_secs()
                    );
                }
                continue;
            }
            Err(e) => {
                tracing::error!("HEP socket recv error: {e}");
                return Err(e).context("Fatal HEP socket error");
            }
        };

        if let Some(outage) = idle_watch.on_packet(Instant::now()) {
            tracing::info!(
                "HEP listener on {bind_addr}: traffic resumed after {}s idle",
                outage.as_secs()
            );
        }

        // Count every datagram received off the socket, not only those
        // ultimately forwarded to the pipeline: `--count N` means "stop after
        // receiving N packets", so a run whose packets are dropped by the
        // allowlist, rate limiter, parser, or auth still makes progress
        // toward the limit rather than appearing to stall.
        count += 1;

        // Check allowlist
        if !allowlist.is_empty() {
            let peer_ip = peer.ip();
            if !allowlist.iter().any(|cidr| cidr.contains(peer_ip)) {
                tracing::debug!("Dropping HEP packet from non-allowed source {peer_ip}");
                continue;
            }
        }

        // Check rate limit (global ceiling + per-peer fairness)
        if !rate_limiter.allow(peer.ip()) {
            continue;
        }

        let hep = match parse_hep(&buf[..n]) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("Skipping malformed HEP packet ({n} bytes): {e}");
                continue;
            }
        };

        // Receiver-side authentication (SN-01): when a secret is configured,
        // the sender must prove it via the 0x000e auth-key chunk. This binds
        // the attacker-asserted inner src/dst metadata to a trusted producer.
        // Plain mode compares the secret verbatim; Hmac mode verifies a
        // per-message token (timestamp + nonce + HMAC over the payload),
        // which also resists on-path replay.
        let auth_pass = match auth_mode {
            HepAuthMode::Plain => hep_auth_ok(auth_key, hep.auth_key.as_deref()),
            HepAuthMode::Hmac => hmac_auth_ok(
                auth_key,
                hep.auth_key.as_deref(),
                &hep.payload,
                hmac_window_secs,
                &mut hmac_nonce_cache,
            ),
        };
        if !auth_pass {
            tracing::debug!(
                "Dropping HEP packet from {}: failed {:?} auth",
                peer.ip(),
                auth_mode
            );
            continue;
        }

        // Convert to a Packet that the rest of the pipeline can process.
        // The HEP chunks (src/dst addr+port, IP protocol) flow into
        // PreParsed so the parser short-circuits the IP-header walk.
        // Provenance is the SENDER, not this listener — see hep_source_label.
        let source = hep_source_label(hep.capture_id, peer.ip());
        let mut packet = hep_to_packet(hep, &source);
        // The other half of the pointer. Stamped from the SENDER's counter,
        // not the listener's, and before the send for the same reason the
        // offline readers stamp before theirs: once the packet is on the
        // shared channel this thread cannot amend it, and the live member of a
        // composite is interleaving its own packets onto the same channel, so
        // arrival order says nothing about position.
        packet.origin = frames.next_origin(&source);

        if tx.send(packet).is_err() {
            tracing::debug!("Receiver dropped, stopping HEP listener");
            break;
        }
    }

    tracing::info!("HEP listener on {bind_addr} finished: {count} packets received");
    Ok(())
}

// ── Deliberate export: a destination the operator named ──────────────
//
// `--hep-send` is the one place sipnab originates traffic outside the
// scanner-kill path, and it is a *different* question from the one
// [`crate::security::transmit_guard::TransmitPermit`] answers.
//
// The kill path aims at an address read out of a packet. On a capture file
// those addresses are historical third parties who never asked to hear from
// this tool, so that path is refused offline and there is no flag to reopen
// it. `--hep-send` aims at a collector the operator typed on the command
// line — their own infrastructure, chosen deliberately — so refusing it on a
// file would break replaying an archived capture into a Homer instance, a
// real workflow. It stays allowed.
//
// What it still owes the operator is a type that says which of those two
// things it is, and a sentence saying what will happen. `HepExportPermit`
// is the type. [`file_export_notice`] is the sentence.
//
// See `docs/design/outbound-transmit-capability.md` for the shape these
// follow, in particular why the two permits must never be interconvertible.

/// The flag an operator types to ask for the HEP export, quoted verbatim in
/// [`file_export_notice`] so the message names what they wrote.
pub const HEP_SEND_FLAG: &str = "--hep-send";

/// A destination the **operator** named — on the command line or in a
/// configuration file — for sipnab to originate traffic at.
///
/// [`from_cli_flag`](Self::from_cli_flag) is the only constructor, and the
/// omissions are the design: there is deliberately no `From<IpAddr>`, no
/// `From<SocketAddr>`, no constructor taking a [`Packet`],
/// [`HepPacket`] or a parsed SIP message. A future call site that wants to
/// export to an address it read out of the capture cannot express it, because
/// there is no function to call — the same trick
/// [`crate::security::transmit_guard::TransmitPermit`]'s private field plays
/// on the capture *source*, applied here to the *destination*.
///
/// That distinction is the whole point. "The operator named this collector"
/// licenses sending them the capture. It licenses nothing about the addresses
/// inside the capture, and the type is what keeps those two apart when the
/// next exporter is written.
#[derive(Debug, Clone)]
pub struct OperatorDestination {
    /// The flag the value arrived on, quoted back in operator-facing text.
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
    /// * `flag` — the flag the operator typed, e.g. [`HEP_SEND_FLAG`].
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

/// Proof that the operator, in this run, named the destination sipnab is
/// about to originate traffic at.
///
/// Constructible only by [`Self::for_destination`], which needs an
/// [`OperatorDestination`], which in turn cannot be built from anything the
/// capture supplied. The private unit field is what makes that the only route.
///
/// **This is not a [`crate::security::transmit_guard::TransmitPermit`] and
/// never converts into one, in either direction.** That permit proves the run
/// watches a live source and licenses answering an address read out of it.
/// This one proves an operator named a destination and licenses nothing about
/// the capture's contents beyond exporting them where they asked. Collapsing
/// the two would silently let a capture-derived address become an export
/// target, with no compile error to mark the loss.
#[derive(Debug, Clone, Copy)]
pub struct HepExportPermit(());

impl HepExportPermit {
    /// Grant the export because `destination` came from the operator.
    ///
    /// There is no failing case: the proof is the argument's *type*, not any
    /// check performed here. Holding an [`OperatorDestination`] already means
    /// the address came through a flag or a config file rather than out of a
    /// packet.
    pub fn for_destination(destination: &OperatorDestination) -> Self {
        // Bound to the destination by construction; nothing further to inspect.
        let _ = destination;
        Self(())
    }
}

/// How many capture file names the export notice lists before summarizing the
/// rest. Enough to recognize the input at a glance, few enough that a
/// `tcpdump -C -W` ring of forty files does not bury the sentence that matters.
const NOTICE_MAX_NAMED_FILES: usize = 3;

/// What an operator must be told when `--hep-send` is pointed at a run that is
/// reading capture FILES: that the contents of those files are what leaves.
///
/// `sipnab -I customer.pcap --hep-send collector:9060` used to log a single
/// line naming the socket — "HEP sender targeting …" — which describes the
/// plumbing, not the consequence. An engineer smoke-testing a HEP pipeline
/// against a customer capture has no reason to read that as "every SIP message
/// in this file is about to leave the machine", and the flag's name says
/// nothing about files. The export is legitimate. The silence was not.
///
/// Deliberately *not* a refusal. The destination is the operator's own, they
/// typed it, and replaying an archive into a collector is a supported
/// workflow — see the module comment above [`OperatorDestination`].
///
/// # Arguments
///
/// * `destination` — the collector the operator named, quoted with its flag.
/// * `paths` — the capture files this run reads, in read order.
///
/// # Returns
///
/// The message to log before the first packet is read. Returns `None` when
/// `paths` is empty, which means the run is not reading files and has nothing
/// to announce.
pub fn file_export_notice(
    destination: &OperatorDestination,
    paths: &[std::path::PathBuf],
) -> Option<String> {
    if paths.is_empty() {
        return None;
    }
    let named: Vec<String> = paths
        .iter()
        .take(NOTICE_MAX_NAMED_FILES)
        .map(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| p.to_string_lossy().into_owned())
        })
        .collect();
    let listed = named.join(", ");
    let remainder = paths.len().saturating_sub(named.len());
    let files = if paths.len() == 1 {
        format!("a capture FILE ({listed})")
    } else if remainder == 0 {
        format!("{} capture FILES ({listed})", paths.len())
    } else {
        format!(
            "{} capture FILES ({listed}, and {remainder} more)",
            paths.len()
        )
    };
    Some(format!(
        "{} {} forwards every SIP message and every RTCP report this run reads \
         to that address, and this run is reading {files}. The signaling in \
         those captures leaves this machine: request lines, headers, URIs, and \
         any message bodies they hold. The RTCP carries the media quality \
         summary alongside it — SSRCs, loss, jitter and the endpoints \
         reporting them — but not the audio, which is never forwarded. sipnab \
         forwards what it does send as it was recorded and redacts nothing. \
         Point {} at a collector you control, or drop it to analyze the \
         captures without forwarding them.",
        destination.flag(),
        destination.as_str(),
        destination.flag(),
    ))
}

// ── HEP sender ───────────────────────────────────────────────────────

/// HEP v3 sender: encapsulates SIP messages as HEP v3 and sends via UDP.
///
/// Create one `HepSender` per destination. Each [`send`](HepSender::send)
/// call builds a HEP v3 packet and transmits it over UDP.
///
/// Every sender carries a [`HepExportPermit`], minted at construction from the
/// [`OperatorDestination`] it targets, and the only function that touches the
/// socket takes that permit. So the export is inside the permit system rather
/// than beside it: an auditor asking "what can put a packet on the network"
/// finds two permits, not one, and neither is reachable without proving
/// something first.
pub struct HepSender {
    /// Underlying UDP socket (connected to the destination).
    socket: UdpSocket,
    /// Capture agent ID included in every HEP packet.
    capture_id: u32,
    /// Optional Homer authenticate key (0x000e chunk) added to every packet.
    auth_key: Option<String>,
    /// How the auth key is presented: verbatim (`Plain`) or as a per-message
    /// HMAC token (`Hmac`).
    auth_mode: HepAuthMode,
    /// Per-sender salt for HMAC-token nonces, mixing time and PID so nonces
    /// do not collide across senders or restarts. The nonce need only be
    /// unique (replay protection), not unpredictable — the HMAC provides
    /// unforgeability — so a salt+counter is sufficient and needs no RNG dep.
    nonce_salt: u64,
    /// Monotonic per-message counter forming the low half of each nonce.
    nonce_counter: std::sync::atomic::AtomicU64,
    /// Proof that the operator named this destination, minted once at
    /// construction and required by [`Self::transmit`]. Held rather than
    /// passed in from outside for the same reason the scanner-kill worker
    /// holds its `TransmitPermit` in a field: the permit is a property of the
    /// thing that was built, and nothing can build this one without it.
    permit: HepExportPermit,
}

impl HepSender {
    /// Create a new HEP sender targeting `dest_addr` (e.g., `"10.0.0.50:9060"`).
    ///
    /// The CLI entry point: `dest_addr` is the raw value of the operator's
    /// `--hep-send` argument, wrapped here into an [`OperatorDestination`].
    /// Prefer [`Self::for_destination`] anywhere the destination has already
    /// been through that type — this wrapper exists because the batch wiring
    /// still passes the flag's string straight through.
    ///
    /// # Arguments
    ///
    /// * `dest_addr` — destination HEP collector address (host:port), **as the
    ///   operator supplied it**. Never an address formatted out of captured
    ///   traffic.
    /// * `capture_id` — capture agent ID stamped into every packet.
    /// * `auth_key` — optional shared secret for the `0x000e` chunk.
    /// * `auth_mode` — how the secret is presented (`Plain` or `Hmac`).
    ///
    /// # Errors
    ///
    /// Returns an error if the destination cannot be resolved or the socket
    /// cannot be created or connected.
    ///
    /// # Side effects
    ///
    /// Those of [`Self::for_destination`].
    pub fn new(
        dest_addr: &str,
        capture_id: u32,
        auth_key: Option<String>,
        auth_mode: HepAuthMode,
    ) -> Result<Self> {
        Self::for_destination(
            &OperatorDestination::from_cli_flag(HEP_SEND_FLAG, dest_addr),
            capture_id,
            auth_key,
            auth_mode,
        )
    }

    /// Create a HEP sender for a destination the operator named.
    ///
    /// Binds an ephemeral local UDP socket, connects it to `destination`, and
    /// mints the [`HepExportPermit`] every send is checked against. Taking an
    /// [`OperatorDestination`] rather than a bare address is what stops a
    /// future call site exporting to something it read out of a packet.
    ///
    /// # Arguments
    ///
    /// * `destination` — the collector the operator named.
    /// * `capture_id` — capture agent ID stamped into every packet.
    /// * `auth_key` — optional shared secret for the `0x000e` chunk.
    /// * `auth_mode` — how the secret is presented (`Plain` or `Hmac`).
    ///
    /// # Errors
    ///
    /// Returns an error if the destination cannot be resolved or the socket
    /// cannot be created or connected.
    ///
    /// # Side effects
    ///
    /// Resolves the destination (may perform a blocking DNS lookup for a
    /// hostname), binds a UDP socket on `[::]:0` for an IPv6 destination or
    /// `0.0.0.0:0` for IPv4 — the bind family must follow the destination or
    /// the connect fails with EAFNOSUPPORT — and connects it; reads the
    /// system clock and process ID to derive the HMAC nonce salt.
    pub fn for_destination(
        destination: &OperatorDestination,
        capture_id: u32,
        auth_key: Option<String>,
        auth_mode: HepAuthMode,
    ) -> Result<Self> {
        use std::net::ToSocketAddrs;
        let permit = HepExportPermit::for_destination(destination);
        let dest_addr = destination.as_str();
        let dest = dest_addr
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve HEP destination '{dest_addr}'"))?
            .next()
            .with_context(|| format!("HEP destination '{dest_addr}' resolved to no addresses"))?;
        let local = if dest.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(local).with_context(|| {
            format!("Failed to bind ephemeral UDP socket ({local}) for HEP sender")
        })?;
        socket
            .connect(dest)
            .with_context(|| format!("Failed to connect HEP sender to '{dest_addr}'"))?;
        let nonce_salt = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ (std::process::id() as u64).rotate_left(32);
        Ok(Self {
            socket,
            capture_id,
            auth_key,
            auth_mode,
            nonce_salt,
            nonce_counter: std::sync::atomic::AtomicU64::new(0),
            permit,
        })
    }

    /// The auth bytes to place in the `0x000e` chunk for `payload`: the key
    /// verbatim in `Plain` mode, or a fresh per-message HMAC token in `Hmac`
    /// mode. `None` when no key is configured.
    fn auth_bytes_for(&self, payload: &[u8]) -> Option<Vec<u8>> {
        let key = self.auth_key.as_deref()?;
        match self.auth_mode {
            HepAuthMode::Plain => Some(key.as_bytes().to_vec()),
            HepAuthMode::Hmac => Some(self.hmac_token(key, payload)),
        }
    }

    /// Build a fresh per-message HMAC token for `payload` under `key`,
    /// using the current time and a salt+counter nonce. Returns the 57-byte
    /// wire token.
    ///
    /// # Side effects
    ///
    /// Reads the system clock and increments the sender's atomic
    /// `nonce_counter` (each call consumes one nonce).
    fn hmac_token(&self, key: &str, payload: &[u8]) -> Vec<u8> {
        use std::sync::atomic::Ordering;
        let ts = chrono::Utc::now().timestamp().max(0) as u64;
        let counter = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.nonce_salt.to_be_bytes());
        nonce[8..].copy_from_slice(&counter.to_be_bytes());
        build_hmac_auth_token(key.as_bytes(), ts, &nonce, payload)
    }

    /// Encapsulate and send a SIP message as a HEP v3 packet.
    ///
    /// Builds the HEP v3 envelope from the SIP message's network metadata
    /// (addresses, ports, timestamp) and the raw SIP bytes, then sends it
    /// over the connected UDP socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP send fails.
    ///
    /// # Side effects
    ///
    /// Transmits one datagram on the connected UDP socket; in `Hmac` auth
    /// mode also reads the clock and increments the atomic nonce counter.
    pub fn send(&self, msg: &crate::sip::message::SipMessage) -> Result<()> {
        let endpoint = HepEndpoint {
            src_addr: msg.src_addr,
            dst_addr: msg.dst_addr,
            src_port: msg.src_port,
            dst_port: msg.dst_port,
            transport: msg.transport,
        };
        self.send_payload(&endpoint, msg.timestamp, HepProtocol::Sip, &msg.raw)
    }

    /// Forward one RTCP datagram, verbatim, as HEP protocol type 5.
    ///
    /// Signaling alone is half an answer. A remote viewer that receives only
    /// SIP can say a call connected and nothing about whether it sounded like
    /// anything — no MOS, no jitter, no loss — which makes it *worse* than
    /// running sngrep on the box, because sngrep at least sees the media.
    /// The receiving side of this module has understood protocol type 5 since
    /// it was written — the protocol-type chunk carries `1=SIP, 5=RTCP,
    /// 32=RTP` — and only the sender never emitted it.
    ///
    /// RTP is deliberately NOT forwarded. RTCP is a control channel that
    /// RFC 3550 §6.2 holds to a small fraction of session bandwidth
    /// (conventionally 5%, with a minimum reporting interval), so it carries
    /// the quality summary at a rate a WAN link and a UDP feed can absorb.
    /// Media itself is the opposite on both counts, and forwarding it would
    /// turn a monitoring feed into a call recorder aimed at somebody's laptop.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP send fails.
    pub fn send_rtcp(
        &self,
        endpoint: &HepEndpoint,
        timestamp: DateTime<Utc>,
        payload: &[u8],
    ) -> Result<()> {
        self.send_payload(endpoint, timestamp, HepProtocol::Rtcp, payload)
    }

    /// Shared by every public send. The permit-guarded [`Self::transmit`] is
    /// reached from here and nowhere else, so adding a protocol does not add a
    /// second answer to "what can put bytes on the network".
    fn send_payload(
        &self,
        endpoint: &HepEndpoint,
        timestamp: DateTime<Utc>,
        protocol: HepProtocol,
        payload: &[u8],
    ) -> Result<()> {
        let auth_bytes = self.auth_bytes_for(payload);
        let pkt = build_hep_v3_bytes(
            endpoint,
            timestamp,
            protocol,
            self.capture_id,
            auth_bytes.as_deref(),
            payload,
        );

        self.transmit(&self.permit, &pkt)
    }

    /// The only function in this module that puts bytes on the network.
    ///
    /// It takes the permit so that "what can transmit" has a single answer an
    /// auditor can reach from the type: reaching this socket needs a
    /// [`HepExportPermit`], which needs an [`OperatorDestination`], which
    /// cannot be built from anything the capture supplied. `_permit` is unread
    /// on purpose — the proof is in holding one, exactly as in the
    /// scanner-kill path's `RawKillSocket::send_to_v4`.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP send fails.
    ///
    /// # Side effects
    ///
    /// Transmits one datagram on the connected UDP socket.
    fn transmit(&self, _permit: &HepExportPermit, pkt: &[u8]) -> Result<()> {
        self.socket
            .send(pkt)
            .with_context(|| "Failed to send HEP v3 packet")?;

        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for HEP v2/v3 parsing and building, receiver-side auth (plain and
/// HMAC), bind policy, rate limiting, and the idle watch.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// `send_rtcp` puts protocol type 5 on the wire, and the payload crosses
    /// verbatim.
    ///
    /// Asserts the EFFECT — a real datagram, received off a real socket and
    /// parsed back — rather than that a builder was handed an enum. That byte
    /// is the whole feature: at type 1 a receiver hands the payload to the SIP
    /// parser, which discards it, and the remote viewer this exists for gets
    /// no MOS, jitter or loss while appearing to work.
    #[test]
    fn send_rtcp_puts_protocol_type_5_on_the_wire() {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("bind collector");
        collector
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let dest = collector.local_addr().expect("collector addr").to_string();

        let sender = HepSender::new(&dest, 42, None, HepAuthMode::Plain).expect("build sender");

        // Minimal RTCP Receiver Report: version 2, PT 201, length 1, one SSRC.
        let rtcp: [u8; 8] = [0x80, 201, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef];
        let endpoint = HepEndpoint {
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            src_port: 5000,
            dst_port: 5001,
            transport: TransportProto::Udp,
        };
        sender
            .send_rtcp(&endpoint, Utc::now(), &rtcp)
            .expect("send_rtcp");

        let mut buf = [0u8; 2048];
        let n = collector
            .recv(&mut buf)
            .expect("receive the forwarded datagram");
        let pkt = parse_hep(&buf[..n]).expect("parse what we just sent");

        assert_eq!(
            pkt.protocol,
            HepProtocol::Rtcp,
            "RTCP must be stamped protocol type 5; type 1 sends it to the SIP \
             parser, which drops it"
        );
        assert_eq!(
            pkt.payload, rtcp,
            "the RTCP report must cross verbatim — a receiver recomputes \
             quality from these bytes"
        );
        assert_eq!(pkt.src_port, 5000, "inner endpoint must survive");
        assert_eq!(pkt.dst_port, 5001, "inner endpoint must survive");
    }

    /// The SIP path still stamps type 1 after `send` was refactored to share
    /// `send_payload` with `send_rtcp`.
    ///
    /// Without this, a swapped argument in the shared helper would send every
    /// SIP message as RTCP and no existing test would notice: both paths would
    /// still put a well-formed HEP datagram on the wire.
    #[test]
    fn send_still_stamps_sip_as_protocol_type_1() {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("bind collector");
        collector
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let dest = collector.local_addr().expect("collector addr").to_string();

        let sender = HepSender::new(&dest, 7, None, HepAuthMode::Plain).expect("build sender");

        let raw = b"OPTIONS sip:a@b SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n";
        let msg = crate::sip::parse_sip(
            raw,
            Utc::now(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("parse the SIP fixture");
        sender.send(&msg).expect("send");

        let mut buf = [0u8; 2048];
        let n = collector.recv(&mut buf).expect("receive");
        let pkt = parse_hep(&buf[..n]).expect("parse");

        assert_eq!(
            pkt.protocol,
            HepProtocol::Sip,
            "SIP must stay protocol type 1"
        );
    }

    /// Two nodes feeding one collector must not collapse into one identity.
    ///
    /// The listener recorded `hep:{bind_addr}` — the address IT listens on —
    /// so every sender in a fan-in produced the same provenance string. A
    /// dialog from the SBC and a dialog from the PBX were indistinguishable by
    /// origin, which is precisely the question a multi-node collector exists to
    /// answer: "which node did this leg come from, and is any node silent?"
    ///
    /// `--hep-id` already exists to distinguish an agent, and the receiver
    /// parsed it (chunk 0x000c) and threw it away.
    #[test]
    fn two_hep_senders_get_distinct_provenance() {
        let a = hep_source_label(Some(7), "192.0.2.10".parse().unwrap());
        let b = hep_source_label(Some(9), "192.0.2.11".parse().unwrap());
        assert_ne!(a, b, "two senders collapsed to one source label");

        // Same box, different agents (two sipnab instances on one host) must
        // still separate — that is what the capture-agent id is for.
        let c = hep_source_label(Some(7), "192.0.2.10".parse().unwrap());
        let d = hep_source_label(Some(8), "192.0.2.10".parse().unwrap());
        assert_ne!(c, d, "same host, different --hep-id collapsed together");

        // A sender that sets no id is still identified by where it came from,
        // rather than by the listener it happened to reach.
        let e = hep_source_label(None, "192.0.2.10".parse().unwrap());
        let f = hep_source_label(None, "192.0.2.11".parse().unwrap());
        assert_ne!(e, f, "id-less senders collapsed to one source label");
        assert!(
            e.contains("192.0.2.10"),
            "an id-less sender must still name its address, got {e:?}"
        );
    }

    /// The label must not name the listener: that is the bug, and a label that
    /// merely ADDED the sender while keeping the bind address would still make
    /// every node share a prefix that reads like the origin.
    #[test]
    fn hep_provenance_names_the_sender_not_the_listener() {
        let label = hep_source_label(Some(7), "192.0.2.10".parse().unwrap());
        assert!(
            !label.contains("0.0.0.0") && !label.contains("9060"),
            "the source label leaks the listener bind address: {label:?}"
        );
        assert!(
            label.contains('7'),
            "the capture-agent id is missing: {label:?}"
        );
    }

    /// EINTR / WouldBlock / TimedOut are transient recv errors (retry);
    /// genuine socket failures are not.
    #[test]
    fn eintr_and_read_timeouts_are_transient_not_fatal() {
        use std::io::ErrorKind;
        // EINTR (a signal interrupting the blocking recv) must be retried, not
        // treated as a fatal socket error — a single SIGCHLD/SIGWINCH would
        // otherwise kill the HEP listener (regression: it did).
        assert!(is_transient_recv_error(ErrorKind::Interrupted));
        // Read-timeout polling errors are also transient.
        assert!(is_transient_recv_error(ErrorKind::WouldBlock));
        assert!(is_transient_recv_error(ErrorKind::TimedOut));
        // A genuinely broken socket is fatal.
        assert!(!is_transient_recv_error(ErrorKind::ConnectionReset));
        assert!(!is_transient_recv_error(ErrorKind::AddrNotAvailable));
    }

    /// Helper: build a minimal valid HEP v3 packet with the given fields.
    #[expect(clippy::too_many_arguments)]
    fn make_hep_v3(
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        ts_sec: u32,
        ts_usec: u32,
        proto: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut chunks = Vec::new();

        // IP family
        let family: u8 = match src {
            IpAddr::V4(_) => 2,
            IpAddr::V6(_) => 10,
        };
        append_chunk(&mut chunks, 0, CHUNK_IP_FAMILY, &[family]);

        // IP proto (UDP)
        append_chunk(&mut chunks, 0, CHUNK_IP_PROTO, &[17]);

        // Addresses
        match src {
            IpAddr::V4(v4) => append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &v4.octets()),
            IpAddr::V6(v6) => append_chunk(&mut chunks, 0, CHUNK_SRC_IPV6, &v6.octets()),
        }
        match dst {
            IpAddr::V4(v4) => append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &v4.octets()),
            IpAddr::V6(v6) => append_chunk(&mut chunks, 0, CHUNK_DST_IPV6, &v6.octets()),
        }

        // Ports
        append_chunk(&mut chunks, 0, CHUNK_SRC_PORT, &src_port.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_DST_PORT, &dst_port.to_be_bytes());

        // Timestamp
        append_chunk(&mut chunks, 0, CHUNK_TS_SEC, &ts_sec.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_TS_USEC, &ts_usec.to_be_bytes());

        // Protocol type
        append_chunk(&mut chunks, 0, CHUNK_PROTO_TYPE, &[proto]);

        // Capture ID
        append_chunk(&mut chunks, 0, CHUNK_CAPTURE_ID, &42u32.to_be_bytes());

        // Payload
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, payload);

        // Assemble final packet
        let total_len = (HEP3_HEADER_LEN + chunks.len()) as u16;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(HEP3_MAGIC);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&chunks);
        pkt
    }

    /// Helper: build a minimal HEP v2 packet.
    fn make_hep_v2(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let header_len: u8 = 16; // version(1) + hdr_len(1) + ports(4) + ips(8) + 2 padding
        let mut pkt = Vec::new();
        pkt.push(HEP2_VERSION);
        pkt.push(header_len);
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());
        // Pad to header_len (already at 14 bytes; need 2 more)
        pkt.extend_from_slice(&[0u8; 2]);
        pkt.extend_from_slice(payload);
        pkt
    }

    /// A well-formed IPv4 HEP v3 packet parses with every field intact.
    #[test]
    fn parse_valid_hep_v3_ipv4() {
        let sip_payload = b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n";
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let data = make_hep_v3(src, dst, 5060, 5061, 1700000000, 123456, 1, sip_payload);

        let hep = parse_hep(&data).expect("parse should succeed");
        assert_eq!(hep.version, 3);
        assert_eq!(hep.src_addr, src);
        assert_eq!(hep.dst_addr, dst);
        assert_eq!(hep.src_port, 5060);
        assert_eq!(hep.dst_port, 5061);
        assert_eq!(hep.protocol, HepProtocol::Sip);
        assert_eq!(hep.payload[..], sip_payload[..]);
        assert_eq!(hep.capture_id, Some(42));
        assert_eq!(hep.timestamp.timestamp(), 1700000000);
    }

    /// A well-formed IPv6 HEP v3 packet parses with the right addresses.
    #[test]
    fn parse_valid_hep_v3_ipv6() {
        let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let payload = b"SIP/2.0 200 OK\r\n\r\n";

        let data = make_hep_v3(src, dst, 5060, 5080, 1700000000, 0, 1, payload);

        let hep = parse_hep(&data).expect("parse should succeed");
        assert_eq!(hep.version, 3);
        assert_eq!(hep.src_addr, src);
        assert_eq!(hep.dst_addr, dst);
        assert_eq!(hep.src_port, 5060);
        assert_eq!(hep.dst_port, 5080);
    }

    /// A well-formed legacy HEP v2 packet parses as SIP with its fixed
    /// header fields extracted.
    #[test]
    fn parse_valid_hep_v2() {
        let payload = b"REGISTER sip:example.com SIP/2.0\r\n\r\n";
        let data = make_hep_v2(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 20),
            5060,
            5060,
            payload,
        );

        let hep = parse_hep(&data).expect("parse should succeed");
        assert_eq!(hep.version, 2);
        assert_eq!(hep.src_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(hep.dst_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)));
        assert_eq!(hep.src_port, 5060);
        assert_eq!(hep.dst_port, 5060);
        assert_eq!(hep.protocol, HepProtocol::Sip);
        assert_eq!(hep.payload[..], payload[..]);
    }

    /// A HEP v3 packet shorter than its 6-byte header is rejected.
    #[test]
    fn parse_truncated_hep_v3_errors() {
        // Too short to even have the header
        let data = b"HEP3\x00";
        assert!(parse_hep(data).is_err());
    }

    /// A declared total_length larger than the received bytes is rejected.
    #[test]
    fn parse_hep_v3_bad_total_length() {
        // total_length claims 1000 bytes but we only have 6
        let mut data = Vec::new();
        data.extend_from_slice(b"HEP3");
        data.extend_from_slice(&1000u16.to_be_bytes());
        assert!(parse_hep(&data).is_err());
    }

    /// A v3 packet without any source-address chunk fails with an error
    /// naming the missing source address.
    #[test]
    fn parse_hep_v3_missing_src_addr() {
        // Build a v3 packet with no source address chunks
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, b"test");

        let total_len = (HEP3_HEADER_LEN + chunks.len()) as u16;
        let mut data = Vec::new();
        data.extend_from_slice(HEP3_MAGIC);
        data.extend_from_slice(&total_len.to_be_bytes());
        data.extend_from_slice(&chunks);

        let err = parse_hep(&data).unwrap_err();
        assert!(
            format!("{err}").contains("source address"),
            "Error should mention missing source address, got: {err}"
        );
    }

    /// Empty input and non-HEP bytes (unknown magic/version) are rejected.
    #[test]
    fn parse_non_hep_data_errors() {
        assert!(parse_hep(b"").is_err());
        assert!(parse_hep(b"\x00\x00\x00\x00").is_err());
        assert!(parse_hep(b"HTTP/1.1 200 OK").is_err());
    }

    /// Truncated HEP v2 packets (bare version byte, or fewer bytes than
    /// the declared header) are rejected.
    #[test]
    fn parse_hep_v2_truncated() {
        // Just the version byte
        assert!(parse_hep(&[0x02]).is_err());
        // Header says 16 bytes but only 10 available
        assert!(parse_hep(&[0x02, 16, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    /// An IPv4 packet built by `build_hep_v3` parses back with every field
    /// (including microsecond timestamp precision) preserved.
    #[test]
    fn build_and_parse_round_trip_ipv4() {
        let src = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2));
        let ts = Utc.timestamp_opt(1700000000, 500_000_000).single().unwrap();
        let payload = b"INVITE sip:alice@example.com SIP/2.0\r\n\r\n";

        let endpoint = HepEndpoint {
            src_addr: src,
            dst_addr: dst,
            src_port: 5060,
            dst_port: 5061,
            transport: TransportProto::Udp,
        };
        let built = build_hep_v3(&endpoint, ts, HepProtocol::Sip, 99, None, payload);
        let parsed = parse_hep(&built).expect("round-trip parse should succeed");

        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.src_addr, src);
        assert_eq!(parsed.dst_addr, dst);
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5061);
        assert_eq!(parsed.protocol, HepProtocol::Sip);
        assert_eq!(parsed.capture_id, Some(99));
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(parsed.timestamp.timestamp(), 1700000000);
        // Microsecond precision: 500_000_000 ns = 500_000 us
        assert_eq!(parsed.timestamp.timestamp_subsec_micros(), 500_000);
    }

    /// The `IP protocol` chunk reports the transport sipnab actually observed.
    ///
    /// It was a literal `17`. Every SIP captured over TCP — and every SIP
    /// recovered from TLS, which `try_tls_decrypt` deliberately stamps as
    /// `Tls` "so the pipeline parses (and reports) the true transport origin" —
    /// reached the collector labeled UDP. A Homer filter on transport was
    /// given a wrong answer with nothing to indicate it.
    ///
    /// Asserted against the wire bytes rather than through `parse_hep`: the
    /// reader defaults a MISSING chunk to UDP, so round-tripping would report
    /// success for a chunk that was never written.
    #[test]
    fn hep_ip_protocol_chunk_follows_the_observed_transport() {
        for (transport, expected, why) in [
            (TransportProto::Udp, 17u8, "UDP"),
            (TransportProto::Tcp, 6, "TCP"),
            (TransportProto::Tls, 6, "TLS rides TCP"),
            (TransportProto::Ws, 6, "WebSocket rides TCP"),
            (TransportProto::Sctp, 132, "SCTP"),
        ] {
            let endpoint = HepEndpoint {
                src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                dst_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                src_port: 5060,
                dst_port: 5060,
                transport,
            };
            let pkt = build_hep_v3(&endpoint, Utc::now(), HepProtocol::Sip, 1, None, b"INVITE");
            let proto = find_hep_chunk(&pkt, 0x0000, CHUNK_IP_PROTO)
                .expect("a HEP packet must carry an IP protocol chunk");
            assert_eq!(
                proto,
                vec![expected],
                "{why}: the IP protocol chunk must report the transport observed, \
                 not a constant"
            );
        }
    }

    /// Walk HEP3 chunks and return the data of the first (vendor,type) match.
    fn find_hep_chunk(pkt: &[u8], vendor: u16, ctype: u16) -> Option<Vec<u8>> {
        let mut i = HEP3_HEADER_LEN;
        while i + CHUNK_HEADER_LEN <= pkt.len() {
            let v = u16::from_be_bytes([pkt[i], pkt[i + 1]]);
            let t = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]);
            let len = u16::from_be_bytes([pkt[i + 4], pkt[i + 5]]) as usize;
            if len < CHUNK_HEADER_LEN || i + len > pkt.len() {
                break;
            }
            if v == vendor && t == ctype {
                return Some(pkt[i + CHUNK_HEADER_LEN..i + len].to_vec());
            }
            i += len;
        }
        None
    }

    /// Helper: a fixed 10.0.0.1:5060 → 10.0.0.2:5060 IPv4 endpoint pair.
    fn v4_endpoint() -> HepEndpoint {
        HepEndpoint {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
        }
    }

    /// With a key configured, the builder emits the `0x000e` auth chunk
    /// carrying the key verbatim.
    #[test]
    fn hep_auth_chunk_emitted_when_key_present() {
        let ts = Utc.timestamp_opt(1700000000, 0).single().unwrap();
        let pkt = build_hep_v3(
            &v4_endpoint(),
            ts,
            HepProtocol::Sip,
            42,
            Some("s3cr3t"),
            b"INVITE",
        );
        // The 0x000e auth-key chunk carries the key verbatim.
        assert_eq!(
            find_hep_chunk(&pkt, 0x0000, 0x000e).as_deref(),
            Some(b"s3cr3t".as_slice())
        );
        // The configured capture/agent id still round-trips.
        assert_eq!(parse_hep(&pkt).unwrap().capture_id, Some(42));
    }

    /// The parser surfaces the `0x000e` auth-key chunk to the receiver.
    #[test]
    fn parse_captures_auth_key_chunk() {
        // The receiver must be able to READ the 0x000e auth-key chunk, not
        // just the sender write it — this is what enables receiver-side
        // authentication (SN-01).
        let ts = Utc.timestamp_opt(1700000000, 0).single().unwrap();
        let pkt = build_hep_v3(
            &v4_endpoint(),
            ts,
            HepProtocol::Sip,
            1,
            Some("s3cr3t"),
            b"INVITE",
        );
        let parsed = parse_hep(&pkt).unwrap();
        assert_eq!(parsed.auth_key.as_deref(), Some(b"s3cr3t".as_slice()));
    }

    /// With no auth chunk on the wire, the parsed `auth_key` is `None`.
    #[test]
    fn parse_auth_key_none_when_absent() {
        let ts = Utc.timestamp_opt(1700000000, 0).single().unwrap();
        let pkt = build_hep_v3(&v4_endpoint(), ts, HepProtocol::Sip, 1, None, b"INVITE");
        assert_eq!(parse_hep(&pkt).unwrap().auth_key, None);
    }

    /// A sender toward an IPv6 collector must bind an IPv6 local socket:
    /// an unconditional `0.0.0.0:0` (IPv4-only) bind makes the connect to
    /// an IPv6 destination fail, so `--hep-send [::1]:9060` cannot work.
    #[test]
    fn hep_sender_to_ipv6_dest_binds_ipv6_socket() {
        let sender = HepSender::new("[::1]:9060", 1, None, HepAuthMode::Plain)
            .expect("sender toward an IPv6 collector must construct");
        let local = sender.socket.local_addr().unwrap();
        assert!(
            local.is_ipv6(),
            "local bind family must be IPv6, got {local}"
        );
    }

    /// The IPv4 destination path is unchanged: local bind stays IPv4.
    #[test]
    fn hep_sender_to_ipv4_dest_binds_ipv4_socket() {
        let sender = HepSender::new("127.0.0.1:9060", 1, None, HepAuthMode::Plain)
            .expect("sender toward an IPv4 collector must construct");
        let local = sender.socket.local_addr().unwrap();
        assert!(
            local.is_ipv4(),
            "local bind family must be IPv4, got {local}"
        );
    }

    /// A destination the operator named reaches the sender through
    /// `for_destination`, and the sender it builds carries the export permit.
    /// Without the permit in the field, [`HepSender::transmit`] could not be
    /// called at all, so this is what puts the export inside the permit system.
    #[test]
    fn a_sender_built_from_an_operator_destination_carries_its_permit() {
        let dest = OperatorDestination::from_cli_flag(HEP_SEND_FLAG, "127.0.0.1:9060");
        assert_eq!(dest.flag(), "--hep-send");
        assert_eq!(dest.as_str(), "127.0.0.1:9060");

        let sender = HepSender::for_destination(&dest, 1, None, HepAuthMode::Plain)
            .expect("an operator-named destination must construct a sender");
        // `transmit` is the only path to the socket and it needs the permit;
        // that this compiles is the assertion.
        sender
            .transmit(&sender.permit, b"HEP3\x00\x06")
            .expect("a connected loopback socket must accept a datagram");
    }

    /// The notice names the flag, the destination and the capture, and says
    /// what leaves. A message that named only the socket is what this
    /// replaces — an operator smoke-testing a HEP pipeline against a customer
    /// capture reads "HEP sender targeting …" without hearing "the capture is
    /// about to leave this machine".
    #[test]
    fn the_file_export_notice_names_the_flag_the_destination_and_the_capture() {
        let dest = OperatorDestination::from_cli_flag(HEP_SEND_FLAG, "collector.example:9060");
        let paths = vec![std::path::PathBuf::from("/cases/4711/customer.pcap")];
        let msg = file_export_notice(&dest, &paths).expect("a file source must produce a notice");

        assert!(msg.contains("--hep-send"), "must name the flag: {msg}");
        assert!(
            msg.contains("collector.example:9060"),
            "must name where the capture goes: {msg}"
        );
        assert!(
            msg.contains("customer.pcap"),
            "must name the capture that leaves: {msg}"
        );
        assert!(
            msg.contains("capture FILE"),
            "must say the source is a file: {msg}"
        );
        assert!(
            msg.contains("redacts nothing"),
            "must say the contents are forwarded as recorded: {msg}"
        );
    }

    /// A `tcpdump -C -W` ring is summarized rather than listed in full: the
    /// count is exact, the first few names are shown, and the sentence stays
    /// readable.
    #[test]
    fn the_file_export_notice_summarises_a_capture_ring() {
        let dest = OperatorDestination::from_cli_flag(HEP_SEND_FLAG, "10.0.0.5:9060");
        let paths: Vec<std::path::PathBuf> = (0..40)
            .map(|i| std::path::PathBuf::from(format!("/cases/ring/tg.pcap{i}")))
            .collect();
        let msg = file_export_notice(&dest, &paths).expect("a file source must produce a notice");

        assert!(
            msg.contains("40 capture FILES"),
            "must give the count: {msg}"
        );
        assert!(msg.contains("tg.pcap0"), "must name the first files: {msg}");
        assert!(
            msg.contains("and 37 more"),
            "must summarize the remainder rather than list 40 names: {msg}"
        );
        assert!(
            !msg.contains("tg.pcap39"),
            "must not list the whole ring: {msg}"
        );
    }

    /// No files, no notice. A live or HEP-fed run forwards traffic the
    /// operator is already watching go past, which is what `--hep-send` reads
    /// like; there is nothing surprising to announce.
    #[test]
    fn a_run_reading_no_files_has_nothing_to_announce() {
        let dest = OperatorDestination::from_cli_flag(HEP_SEND_FLAG, "10.0.0.5:9060");
        assert!(
            file_export_notice(&dest, &[]).is_none(),
            "only a file source forwards a stored capture"
        );
    }

    /// With no receiver secret configured, every packet passes auth.
    #[test]
    fn verify_hep_auth_accepts_all_when_no_secret_configured() {
        // Backward compatible: with no receiver secret, any packet passes
        // (with or without an auth chunk).
        assert!(hep_auth_ok(None, Some(b"anything")));
        assert!(hep_auth_ok(None, None));
    }

    /// With a secret configured, only an exact key match passes; missing,
    /// wrong, and prefix-extended keys are rejected.
    #[test]
    fn verify_hep_auth_requires_matching_key_when_secret_configured() {
        assert!(
            hep_auth_ok(Some("secret"), Some(b"secret")),
            "exact match accepted"
        );
        assert!(
            !hep_auth_ok(Some("secret"), Some(b"wrong")),
            "mismatch rejected"
        );
        assert!(!hep_auth_ok(Some("secret"), None), "missing chunk rejected");
        assert!(
            !hep_auth_ok(Some("secret"), Some(b"secretX")),
            "prefix not accepted"
        );
    }

    /// An unguarded non-loopback bind (no auth, no allowlist) is refused.
    #[test]
    fn hep_bind_policy_refuses_non_loopback_without_auth_or_allowlist() {
        let err = enforce_hep_bind_policy("0.0.0.0:9060", false, 0).unwrap_err();
        assert!(err.contains("non-loopback"), "got: {err}");
    }

    /// IPv4 and IPv6 loopback binds are allowed without auth or allowlist.
    #[test]
    fn hep_bind_policy_allows_loopback_unauthenticated() {
        assert!(enforce_hep_bind_policy("127.0.0.1:9060", false, 0).is_ok());
        assert!(enforce_hep_bind_policy("[::1]:9060", false, 0).is_ok());
    }

    /// Either a shared secret or a non-empty allowlist permits a
    /// non-loopback bind.
    #[test]
    fn hep_bind_policy_allows_non_loopback_with_auth_or_allowlist() {
        assert!(
            enforce_hep_bind_policy("0.0.0.0:9060", true, 0).is_ok(),
            "auth suffices"
        );
        assert!(
            enforce_hep_bind_policy("0.0.0.0:9060", false, 1).is_ok(),
            "allowlist suffices"
        );
    }

    /// Loopback classification is purely syntactic: literal loopback IPs are
    /// loopback; routable literals are not. No DNS resolution happens.
    #[test]
    fn hep_bind_loopback_classifies_literals() {
        assert!(hep_bind_is_loopback("127.0.0.1:9060"));
        assert!(hep_bind_is_loopback("[::1]:9060"));
        assert!(!hep_bind_is_loopback("0.0.0.0:9060"));
        assert!(!hep_bind_is_loopback("192.0.2.1:9060"));
    }

    /// A hostname is NOT resolved to decide loopback-ness (no blocking DNS in
    /// a security check); it is treated conservatively as non-loopback, and
    /// `enforce_hep_bind_policy` therefore fail-closes it without auth/allowlist.
    #[test]
    fn hep_bind_hostname_is_conservatively_non_loopback() {
        assert!(
            !hep_bind_is_loopback("localhost:9060"),
            "a hostname must not be resolved and must count as non-loopback"
        );
        assert!(!hep_bind_is_ip_literal("localhost:9060"));
        assert!(hep_bind_is_ip_literal("127.0.0.1:9060"));
        // Unguarded hostname bind is refused (fail closed), same as any other
        // non-loopback address.
        assert!(
            enforce_hep_bind_policy("localhost:9060", false, 0).is_err(),
            "hostname bind without auth or allowlist must be refused"
        );
        // With auth it is permitted (the warning about the non-literal is a
        // startup log, not a refusal).
        assert!(enforce_hep_bind_policy("localhost:9060", true, 0).is_ok());
    }

    /// The global ceiling drops the excess packet regardless of which peer
    /// sends it.
    #[test]
    fn per_peer_limiter_global_ceiling_drops_excess() {
        // Global ceiling of 2/s: the third packet in a window is dropped
        // regardless of peer.
        let mut lim = HepRateLimiter::new(2, 100, crate::rate_limit::DEFAULT_MAX_TRACKED_PEERS);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(lim.allow(a));
        assert!(lim.allow(b));
        assert!(!lim.allow(a), "global ceiling of 2 reached");
    }

    /// The per-peer cap throttles a flooding peer without consuming a
    /// quiet peer's allowance.
    #[test]
    fn per_peer_limiter_isolates_noisy_peer() {
        // Per-peer cap of 1 with a generous global ceiling: a flooding peer
        // is throttled without consuming another peer's allowance.
        let mut lim = HepRateLimiter::new(1000, 1, crate::rate_limit::DEFAULT_MAX_TRACKED_PEERS);
        let noisy: IpAddr = "10.0.0.1".parse().unwrap();
        let quiet: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(lim.allow(noisy));
        assert!(!lim.allow(noisy), "noisy peer hit its per-peer cap");
        assert!(lim.allow(quiet), "quiet peer still gets its own allowance");
    }

    /// Once the per-peer tracking map is full, a brand-new peer is dropped
    /// rather than bypassing the per-peer cap — a many-source-IP flood must
    /// not get a free pass just because it exhausted the tracking table.
    #[test]
    fn per_peer_limiter_full_map_drops_new_peer() {
        // Effectively unlimited global ceiling so only the per-peer path (and
        // the map-full guard) can drop.
        let mut lim =
            HepRateLimiter::new(u64::MAX, 1, crate::rate_limit::DEFAULT_MAX_TRACKED_PEERS);
        // Fill the tracking map with the maximum number of distinct peers;
        // each fresh peer's first packet is allowed.
        for i in 0..crate::rate_limit::DEFAULT_MAX_TRACKED_PEERS as u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            assert!(lim.allow(ip), "first packet from fresh peer {i} allowed");
        }
        // A new peer beyond the tracking cap must be dropped, not waved
        // through the (now-skipped) per-peer check.
        let newcomer = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
        assert!(
            !lim.allow(newcomer),
            "new peer past the tracking cap must be dropped, not bypass the cap"
        );
    }

    /// The startup summary renders per-peer 0 as "disabled" and non-zero
    /// values as a rate.
    #[test]
    fn describe_limiters_reports_per_peer_state() {
        assert_eq!(
            describe_hep_limiters(50000, 0),
            "HEP rate limiting: global 50000/s, per-peer disabled"
        );
        assert_eq!(
            describe_hep_limiters(40000, 10000),
            "HEP rate limiting: global 40000/s, per-peer 10000/s"
        );
    }

    /// A global ceiling of 0 means DISABLED (matching the per-peer knob),
    /// not "drop everything": every packet passes when only the global limit
    /// is 0.
    #[test]
    fn global_rate_limit_zero_disables_ceiling() {
        let mut lim = HepRateLimiter::new(0, 0, crate::rate_limit::DEFAULT_MAX_TRACKED_PEERS);
        let p: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..10_000 {
            assert!(lim.allow(p), "global 0 must disable the ceiling, not drop");
        }
    }

    /// The startup summary renders a global ceiling of 0 as "disabled" so the
    /// knob reads consistently with the per-peer summary.
    #[test]
    fn describe_limiters_reports_global_disabled() {
        assert_eq!(
            describe_hep_limiters(0, 0),
            "HEP rate limiting: global disabled, per-peer disabled"
        );
        assert_eq!(
            describe_hep_limiters(0, 5000),
            "HEP rate limiting: global disabled, per-peer 5000/s"
        );
    }

    /// Tests for the HMAC auth-token build/verify cycle: format, timestamp
    /// window, MAC binding, and replay protection.
    #[cfg(feature = "hep")]
    mod hmac_auth {
        use super::super::*;

        /// Shared HMAC key used by every test in this module.
        const KEY: &[u8] = b"shared-hmac-key";
        /// Fixed 16-byte nonce used across tests (uniqueness not needed here).
        const NONCE: [u8; 16] = [7u8; 16];
        /// Fixed "current time" (epoch seconds) the tests verify against.
        const NOW: u64 = 1_700_000_000;

        /// A freshly built token has the expected length and verifies
        /// against the same key/payload/time.
        #[test]
        fn token_round_trips_and_verifies() {
            let payload = b"REGISTER sip:example.com SIP/2.0\r\n";
            let token = build_hmac_auth_token(KEY, NOW, &NONCE, payload);
            assert_eq!(token.len(), 1 + 8 + 16 + 32);
            let mut cache = HmacNonceCache::new();
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &token,
                    payload,
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Ok(())
            );
        }

        /// A short token or an unknown version byte fails as `BadFormat`.
        #[test]
        fn verify_rejects_bad_length_and_version() {
            let mut cache = HmacNonceCache::new();
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    b"short",
                    b"p",
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Err(HmacAuthError::BadFormat)
            );
            let mut token = build_hmac_auth_token(KEY, NOW, &NONCE, b"p");
            token[0] = 9; // unknown version
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &token,
                    b"p",
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Err(HmacAuthError::BadFormat)
            );
        }

        /// Timestamps beyond the window — stale or future — fail as
        /// `TimestampOutOfWindow`.
        #[test]
        fn verify_rejects_stale_and_future_timestamps() {
            let payload = b"p";
            let mut cache = HmacNonceCache::new();
            let stale = build_hmac_auth_token(KEY, NOW - 100, &NONCE, payload);
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &stale,
                    payload,
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Err(HmacAuthError::TimestampOutOfWindow)
            );
            let future = build_hmac_auth_token(KEY, NOW + 100, &NONCE, payload);
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &future,
                    payload,
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Err(HmacAuthError::TimestampOutOfWindow)
            );
        }

        /// A tampered payload or a wrong key both fail as `BadMac`,
        /// proving the MAC binds the payload, not just the key.
        #[test]
        fn verify_rejects_tampered_payload_and_wrong_key() {
            let token = build_hmac_auth_token(KEY, NOW, &NONCE, b"original-payload");
            let mut cache = HmacNonceCache::new();
            // Same token, different payload → MAC mismatch.
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &token,
                    b"tampered-payload",
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Err(HmacAuthError::BadMac)
            );
            // Right payload, wrong key → MAC mismatch.
            assert_eq!(
                verify_hmac_auth_token(
                    b"attacker-key",
                    &token,
                    b"original-payload",
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Err(HmacAuthError::BadMac)
            );
        }

        /// An identical token replayed within the window fails as `Replay`.
        #[test]
        fn verify_rejects_replayed_nonce() {
            let payload = b"INVITE";
            let token = build_hmac_auth_token(KEY, NOW, &NONCE, payload);
            let mut cache = HmacNonceCache::new();
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &token,
                    payload,
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Ok(()),
                "first use accepted"
            );
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &token,
                    payload,
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Err(HmacAuthError::Replay),
                "identical replay rejected"
            );
        }

        /// End to end: token stamped into the `0x000e` chunk survives the
        /// wire round trip and verifies against the parsed payload.
        #[test]
        fn hep_v3_round_trips_through_build_parse_verify() {
            // End to end: a sender stamps the token into the 0x000e chunk, the
            // wire packet parses back, and the receiver verifies the token
            // against the parsed payload — proving the on-wire format composes.
            use std::net::IpAddr;
            let payload = b"OPTIONS sip:probe SIP/2.0\r\n";
            let token = build_hmac_auth_token(KEY, NOW, &NONCE, payload);
            let endpoint = HepEndpoint {
                src_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
                dst_addr: "10.0.0.2".parse::<IpAddr>().unwrap(),
                src_port: 5060,
                dst_port: 5060,
                transport: TransportProto::Udp,
            };
            let pkt = build_hep_v3_bytes(
                &endpoint,
                chrono::Utc::now(),
                HepProtocol::Sip,
                1,
                Some(&token),
                payload,
            );
            let parsed = parse_hep(&pkt).expect("valid HEP v3");
            assert_eq!(parsed.auth_key.as_deref(), Some(token.as_slice()));
            assert_eq!(parsed.payload, payload);
            let mut cache = HmacNonceCache::new();
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &token,
                    &parsed.payload,
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Ok(())
            );
        }

        /// Pruning is amortized: the first call prunes, then at most once per
        /// second, so an accepted-packet burst does not walk the whole nonce
        /// map on every packet.
        #[test]
        fn nonce_cache_amortizes_pruning() {
            let mut cache = HmacNonceCache::new();
            let t0 = Instant::now();
            assert!(cache.should_prune(t0), "first prune always runs");
            assert!(
                !cache.should_prune(t0 + Duration::from_millis(200)),
                "no second prune within the same second"
            );
            assert!(
                !cache.should_prune(t0 + Duration::from_millis(999)),
                "still within a second of the last prune"
            );
            assert!(
                cache.should_prune(t0 + Duration::from_millis(1000)),
                "prune runs again once a full second has elapsed"
            );
            assert!(
                !cache.should_prune(t0 + Duration::from_millis(1500)),
                "the gate resets relative to the most recent prune"
            );
        }

        /// An expired nonce that has not yet been pruned still cannot be
        /// replayed: the timestamp-window check rejects it before the replay
        /// cache is consulted, so amortized pruning preserves the semantics.
        #[test]
        fn expired_unpruned_nonce_still_rejected_by_window() {
            let mut cache = HmacNonceCache::new();
            // Accept a token now, seeding its nonce into the cache.
            let token = build_hmac_auth_token(KEY, NOW, &NONCE, b"p");
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &token,
                    b"p",
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Ok(())
            );
            // Far in the future the same token is out of window — rejected as
            // stale regardless of whether its nonce is still cached.
            let later = NOW + DEFAULT_HMAC_WINDOW_SECS + 100;
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &token,
                    b"p",
                    later,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Err(HmacAuthError::TimestampOutOfWindow)
            );
        }

        /// A forged (bad-MAC) token must not record its nonce, so a later
        /// authentic token reusing that nonce still verifies.
        #[test]
        fn forged_token_does_not_poison_replay_cache() {
            // A forged token (valid nonce, bad MAC) must be rejected as BadMac
            // and must NOT record its nonce, so a later authentic token reusing
            // that nonce still verifies (MAC-checked-before-replay ordering).
            let payload = b"OPTIONS";
            let mut forged = build_hmac_auth_token(b"wrong-key", NOW, &NONCE, payload);
            let last = forged.len() - 1;
            forged[last] ^= 0xFF; // ensure MAC is wrong even if keys collide
            let mut cache = HmacNonceCache::new();
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &forged,
                    payload,
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Err(HmacAuthError::BadMac)
            );
            let authentic = build_hmac_auth_token(KEY, NOW, &NONCE, payload);
            assert_eq!(
                verify_hmac_auth_token(
                    KEY,
                    &authentic,
                    payload,
                    NOW,
                    DEFAULT_HMAC_WINDOW_SECS,
                    &mut cache
                ),
                Ok(()),
                "authentic token with the same nonce still accepted"
            );
        }
    }

    /// An auth key containing backslashes/colons/slashes round-trips
    /// verbatim in the `0x000e` chunk.
    #[test]
    fn hep_auth_chunk_handles_special_bytes() {
        // An auth key with backslashes / colons / slashes must round-trip
        // verbatim in the 0x000e chunk (no escaping or truncation).
        let ts = Utc.timestamp_opt(1700000000, 0).single().unwrap();
        let key = "k3y\\with:special/chars";
        let pkt = build_hep_v3(&v4_endpoint(), ts, HepProtocol::Sip, 7, Some(key), b"X");
        assert_eq!(
            find_hep_chunk(&pkt, 0x0000, 0x000e).as_deref(),
            Some(key.as_bytes())
        );
    }

    /// A non-default capture agent ID is emitted and parses back intact.
    #[test]
    fn hep_custom_capture_id_round_trips() {
        // A non-default capture/agent id is emitted and parses back.
        let ts = Utc.timestamp_opt(1700000000, 0).single().unwrap();
        let pkt = build_hep_v3(&v4_endpoint(), ts, HepProtocol::Sip, 4242, None, b"X");
        assert_eq!(parse_hep(&pkt).unwrap().capture_id, Some(4242));
    }

    /// With no key configured, the builder omits the `0x000e` chunk while
    /// still producing a valid packet.
    #[test]
    fn hep_no_auth_chunk_when_key_absent() {
        let ts = Utc.timestamp_opt(1700000000, 0).single().unwrap();
        let pkt = build_hep_v3(&v4_endpoint(), ts, HepProtocol::Sip, 1, None, b"INVITE");
        assert!(
            find_hep_chunk(&pkt, 0x0000, 0x000e).is_none(),
            "no auth chunk should be emitted without a key"
        );
        // The packet is still a valid HEP3 message.
        assert!(parse_hep(&pkt).is_ok());
    }

    /// TS_SEC is a fixed u32 seconds-since-epoch wire field; a capture time
    /// outside 1970-01-01..2106-02-07 clamps to the u32 range instead of
    /// silently wrapping through `as u32`.
    #[test]
    fn hep_ts_sec_clamps_to_u32_range() {
        // Post-2106: seconds beyond u32::MAX clamp to u32::MAX, not wrap.
        let far_future = Utc.timestamp_opt(5_000_000_000, 0).single().unwrap();
        let pkt = build_hep_v3(&v4_endpoint(), far_future, HepProtocol::Sip, 1, None, b"X");
        assert_eq!(
            find_hep_chunk(&pkt, 0x0000, CHUNK_TS_SEC).as_deref(),
            Some(&u32::MAX.to_be_bytes()[..]),
            "post-2106 timestamp must clamp to u32::MAX"
        );
        // Pre-1970: negative seconds clamp to 0, not wrap to a huge u32.
        let pre_epoch = Utc.timestamp_opt(-100, 0).single().unwrap();
        let pkt = build_hep_v3(&v4_endpoint(), pre_epoch, HepProtocol::Sip, 1, None, b"X");
        assert_eq!(
            find_hep_chunk(&pkt, 0x0000, CHUNK_TS_SEC).as_deref(),
            Some(&0u32.to_be_bytes()[..]),
            "pre-1970 timestamp must clamp to 0"
        );
        // A normal, in-range timestamp is unchanged.
        let normal = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        let pkt = build_hep_v3(&v4_endpoint(), normal, HepProtocol::Sip, 1, None, b"X");
        assert_eq!(
            find_hep_chunk(&pkt, 0x0000, CHUNK_TS_SEC).as_deref(),
            Some(&1_700_000_000u32.to_be_bytes()[..]),
            "in-range timestamp must pass through unchanged"
        );
    }

    /// An IPv6 RTP packet built by `build_hep_v3` parses back with its
    /// addresses and ports preserved.
    #[test]
    fn build_and_parse_round_trip_ipv6() {
        let src = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let dst = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
        let ts = Utc.timestamp_opt(1700000000, 0).single().unwrap();
        let payload = b"BYE sip:test@example.com SIP/2.0\r\n\r\n";

        let endpoint = HepEndpoint {
            src_addr: src,
            dst_addr: dst,
            src_port: 6000,
            dst_port: 7000,
            transport: TransportProto::Udp,
        };
        let built = build_hep_v3(&endpoint, ts, HepProtocol::Rtp, 1, None, payload);
        let parsed = parse_hep(&built).expect("round-trip parse should succeed");

        assert_eq!(parsed.src_addr, src);
        assert_eq!(parsed.dst_addr, dst);
        assert_eq!(parsed.src_port, 6000);
        assert_eq!(parsed.dst_port, 7000);
        assert_eq!(parsed.protocol, HepProtocol::Rtp);
    }

    /// `HepProtocol` byte encode/decode is a bijection for known and
    /// unknown protocol values.
    #[test]
    fn hep_protocol_round_trip() {
        assert_eq!(HepProtocol::from_byte(1), HepProtocol::Sip);
        assert_eq!(HepProtocol::from_byte(5), HepProtocol::Rtcp);
        assert_eq!(HepProtocol::from_byte(32), HepProtocol::Rtp);
        assert_eq!(HepProtocol::from_byte(99), HepProtocol::Unknown(99));

        assert_eq!(HepProtocol::Sip.to_byte(), 1);
        assert_eq!(HepProtocol::Rtcp.to_byte(), 5);
        assert_eq!(HepProtocol::Rtp.to_byte(), 32);
        assert_eq!(HepProtocol::Unknown(42).to_byte(), 42);
    }

    /// A chunk claiming more bytes than the packet holds is rejected.
    #[test]
    fn hep_v3_chunk_overflow_rejected() {
        // Build a packet where a chunk claims to be longer than remaining data
        let mut data = Vec::new();
        data.extend_from_slice(HEP3_MAGIC);
        // total_len = 6 (header) + 6 (one chunk header that claims 100 bytes) = 12
        // but the chunk says it's 100 bytes, which overflows
        let total_len: u16 = 12;
        data.extend_from_slice(&total_len.to_be_bytes());
        // chunk: vendor=0, type=1, length=100
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&100u16.to_be_bytes());

        assert!(parse_hep(&data).is_err());
    }

    /// Issue #5 regression: verify the HEP→Packet conversion preserves
    /// addressing as `pre_parsed` metadata so the parser can short-circuit.
    /// Previously the listener tagged DLT_RAW with payload-only data,
    /// causing the parser to mis-read the SIP body as an IP header.
    #[test]
    fn hep_to_packet_attaches_pre_parsed_metadata() {
        let payload = b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n";
        let hep = HepPacket {
            version: 3,
            src_addr: "192.0.2.10".parse().unwrap(),
            dst_addr: "192.0.2.20".parse().unwrap(),
            src_port: 5060,
            dst_port: 5060,
            timestamp: Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            protocol: HepProtocol::Sip,
            payload: payload.to_vec(),
            correlation_id: None,
            capture_id: None,
            auth_key: None,
            ip_protocol: 17,
        };
        let packet = hep_to_packet(hep, "0.0.0.0:9060");
        let meta = packet
            .pre_parsed
            .as_ref()
            .expect("pre_parsed must be set so parser short-circuits");
        assert_eq!(meta.src_addr, "192.0.2.10".parse::<IpAddr>().unwrap());
        assert_eq!(meta.dst_addr, "192.0.2.20".parse::<IpAddr>().unwrap());
        assert_eq!(meta.src_port, 5060);
        assert_eq!(meta.dst_port, 5060);
        assert_eq!(meta.ip_protocol, 17);
        assert_eq!(&packet.data[..], &payload[..]);
    }

    /// HEP packets that carry TCP-borne SIP must surface `ip_protocol = 6`
    /// so downstream consumers see TransportProto::Tcp.
    #[test]
    fn hep_to_packet_preserves_tcp_protocol() {
        let hep = HepPacket {
            version: 3,
            src_addr: "192.168.1.10".parse().unwrap(),
            dst_addr: "192.168.1.20".parse().unwrap(),
            src_port: 5060,
            dst_port: 5061,
            timestamp: Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            protocol: HepProtocol::Sip,
            payload: b"REGISTER sip:carol SIP/2.0\r\n\r\n".to_vec(),
            correlation_id: None,
            capture_id: None,
            auth_key: None,
            ip_protocol: 6,
        };
        let packet = hep_to_packet(hep, "0.0.0.0:9060");
        let meta = packet.pre_parsed.as_ref().unwrap();
        assert_eq!(meta.ip_protocol, 6);
    }

    /// Default IP protocol when a HEP packet omits CHUNK_IP_PROTO is UDP,
    /// matching the most common HEP payload (SIP/UDP, RTP/UDP).
    #[test]
    fn parse_hep_defaults_ip_protocol_to_udp_when_chunk_missing() {
        // Build a HEP v3 packet that intentionally omits CHUNK_IP_PROTO.
        let payload = b"OPTIONS sip:test SIP/2.0\r\n\r\n";
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_IP_FAMILY, &[2]);
        append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &[10, 0, 0, 2]);
        append_chunk(&mut chunks, 0, CHUNK_SRC_PORT, &5060u16.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_DST_PORT, &5060u16.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_TS_SEC, &0u32.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_TS_USEC, &0u32.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_PROTO_TYPE, &[1]);
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, payload);

        let mut data = Vec::new();
        data.extend_from_slice(HEP3_MAGIC);
        let total_len = (HEP3_HEADER_LEN + chunks.len()) as u16;
        data.extend_from_slice(&total_len.to_be_bytes());
        data.extend_from_slice(&chunks);

        let parsed = parse_hep(&data).expect("HEP parse");
        assert_eq!(parsed.ip_protocol, 17);
    }

    // ── IdleWatch: silent-stall detection ────────────────────────────

    use std::time::Instant;

    /// Helper: a fresh `Instant` origin for the idle-watch tests (offsets
    /// are added to it, so no sleeping is needed).
    fn t0() -> Instant {
        Instant::now()
    }

    /// Below the threshold, `check` stays quiet.
    #[test]
    fn idle_watch_quiet_below_threshold() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        assert_eq!(w.check(start + Duration::from_secs(29)), None);
    }

    /// Crossing the threshold warns exactly once — repeated polls during
    /// the same idle period stay silent.
    #[test]
    fn idle_watch_warns_once_when_threshold_crossed() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        let idle = w.check(start + Duration::from_secs(31));
        assert_eq!(idle, Some(Duration::from_secs(31)));
        // Repeated checks while still idle must NOT warn again (no log spam).
        assert_eq!(w.check(start + Duration::from_secs(60)), None);
        assert_eq!(w.check(start + Duration::from_secs(600)), None);
    }

    /// The first packet after a warned idle period reports the full outage
    /// duration; steady traffic afterwards is silent.
    #[test]
    fn idle_watch_reports_recovery_with_total_idle_time() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        assert!(w.check(start + Duration::from_secs(40)).is_some());
        // First packet after a warned idle period reports the outage length.
        let recovered = w.on_packet(start + Duration::from_secs(100));
        assert_eq!(recovered, Some(Duration::from_secs(100)));
        // Steady traffic afterwards is silent.
        assert_eq!(w.on_packet(start + Duration::from_secs(101)), None);
    }

    /// Each packet restarts the idle clock; the threshold is measured from
    /// the last packet, not from creation.
    #[test]
    fn idle_watch_packet_resets_idle_clock() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        assert_eq!(w.on_packet(start + Duration::from_secs(20)), None);
        // 29s after the last packet (49s after start): still quiet.
        assert_eq!(w.check(start + Duration::from_secs(49)), None);
        // 31s after the last packet: warn.
        assert!(w.check(start + Duration::from_secs(51)).is_some());
    }

    /// After a recovery, a second outage produces a second warning.
    #[test]
    fn idle_watch_can_warn_again_after_recovery() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::from_secs(30), start);
        assert!(w.check(start + Duration::from_secs(31)).is_some());
        assert!(w.on_packet(start + Duration::from_secs(40)).is_some());
        // A second outage warns again.
        assert!(w.check(start + Duration::from_secs(80)).is_some());
    }

    /// A zero threshold disables the watch entirely: no warnings, no
    /// recovery reports.
    #[test]
    fn idle_watch_zero_threshold_is_disabled() {
        let start = t0();
        let mut w = IdleWatch::new(Duration::ZERO, start);
        assert_eq!(w.check(start + Duration::from_secs(3600)), None);
        assert_eq!(w.on_packet(start + Duration::from_secs(7200)), None);
    }

    // ── Malformed / edge HEP v3 parsing ──────────────────────────────

    /// Helper: assemble a HEP v3 packet from a pre-built chunk buffer,
    /// computing the magic + total_length header. Lets a test craft
    /// individual (possibly malformed) chunks precisely.
    fn assemble_v3(chunks: &[u8]) -> Vec<u8> {
        let total_len = (HEP3_HEADER_LEN + chunks.len()) as u16;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(HEP3_MAGIC);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(chunks);
        pkt
    }

    /// A chunk whose declared length is below the 6-byte header minimum
    /// must be rejected (guards against an offset that never advances).
    #[test]
    fn parse_hep_v3_chunk_len_below_header_rejected() {
        let mut chunks = Vec::new();
        // vendor=0, type=SRC_IPV4, length=3 (illegal: < CHUNK_HEADER_LEN)
        chunks.extend_from_slice(&0u16.to_be_bytes());
        chunks.extend_from_slice(&CHUNK_SRC_IPV4.to_be_bytes());
        chunks.extend_from_slice(&3u16.to_be_bytes());
        let data = assemble_v3(&chunks);
        let err = parse_hep(&data).unwrap_err();
        assert!(
            format!("{err}").contains("smaller than header"),
            "expected header-min error, got: {err}"
        );
    }

    /// A zero-length declared chunk is the degenerate case of the
    /// below-header check and must also be rejected (it would otherwise
    /// loop forever without advancing `offset`).
    #[test]
    fn parse_hep_v3_zero_length_chunk_rejected() {
        let mut chunks = Vec::new();
        chunks.extend_from_slice(&0u16.to_be_bytes());
        chunks.extend_from_slice(&CHUNK_IP_FAMILY.to_be_bytes());
        chunks.extend_from_slice(&0u16.to_be_bytes()); // length = 0
        let data = assemble_v3(&chunks);
        assert!(parse_hep(&data).is_err());
    }

    /// `total_length` smaller than the 6-byte header leaves the chunk
    /// loop with nothing to walk; the packet then lacks required address
    /// chunks and must error on the missing source address.
    #[test]
    fn parse_hep_v3_total_len_below_header() {
        let mut data = Vec::new();
        data.extend_from_slice(HEP3_MAGIC);
        data.extend_from_slice(&3u16.to_be_bytes()); // total_len = 3 < header
        // pad so the slice itself is long enough to read the header
        data.extend_from_slice(&[0u8, 0u8]);
        let err = parse_hep(&data).unwrap_err();
        assert!(
            format!("{err}").contains("source address"),
            "expected missing-source error, got: {err}"
        );
    }

    /// A v3 packet carrying source but no destination address chunk must
    /// fail with a destination-address error (mirrors the src-addr test).
    #[test]
    fn parse_hep_v3_missing_dst_addr() {
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, b"test");
        let data = assemble_v3(&chunks);
        let err = parse_hep(&data).unwrap_err();
        assert!(
            format!("{err}").contains("destination address"),
            "expected missing-destination error, got: {err}"
        );
    }

    /// Each fixed-width chunk has a minimum-length guard. A truncated
    /// chunk body (e.g. a 3-byte SRC_IPV4) must be rejected rather than
    /// reading past the declared data.
    #[test]
    fn parse_hep_v3_short_fixed_chunks_rejected() {
        // (chunk_type, too-short data, expected error fragment)
        let cases: &[(u16, &[u8], &str)] = &[
            (CHUNK_IP_PROTO, &[], "IP_PROTO chunk too short"),
            (CHUNK_SRC_IPV4, &[1, 2, 3], "SRC_IPV4 chunk too short"),
            (CHUNK_DST_IPV4, &[1, 2, 3], "DST_IPV4 chunk too short"),
            (CHUNK_SRC_IPV6, &[0; 8], "SRC_IPV6 chunk too short"),
            (CHUNK_DST_IPV6, &[0; 8], "DST_IPV6 chunk too short"),
            (CHUNK_SRC_PORT, &[1], "SRC_PORT chunk too short"),
            (CHUNK_DST_PORT, &[1], "DST_PORT chunk too short"),
            (CHUNK_TS_SEC, &[1, 2], "TS_SEC chunk too short"),
            (CHUNK_TS_USEC, &[1, 2], "TS_USEC chunk too short"),
            (CHUNK_PROTO_TYPE, &[], "PROTO_TYPE chunk too short"),
            (CHUNK_CAPTURE_ID, &[1, 2], "CAPTURE_ID chunk too short"),
        ];
        for (ty, body, frag) in cases {
            let mut chunks = Vec::new();
            append_chunk(&mut chunks, 0, *ty, body);
            let data = assemble_v3(&chunks);
            let err = parse_hep(&data).unwrap_err();
            assert!(
                format!("{err}").contains(frag),
                "chunk type {ty:#06x}: expected `{frag}`, got: {err}"
            );
        }
    }

    /// Unknown vendor chunks and the informational IP_FAMILY chunk are
    /// skipped without aborting the parse: a packet that mixes them with
    /// the required chunks still parses cleanly.
    #[test]
    fn parse_hep_v3_skips_unknown_and_family_chunks() {
        let mut chunks = Vec::new();
        // Informational family chunk (a no-op branch in the parser).
        append_chunk(&mut chunks, 0, CHUNK_IP_FAMILY, &[2]);
        // Unknown chunk type with a non-zero vendor — must be skipped.
        append_chunk(&mut chunks, 0x1234, 0x7fff, b"ignored-vendor-data");
        append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &[10, 0, 0, 2]);
        append_chunk(&mut chunks, 0, CHUNK_SRC_PORT, &5060u16.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_DST_PORT, &5061u16.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, b"PING");
        let data = assemble_v3(&chunks);

        let hep = parse_hep(&data).expect("unknown chunks should be skipped");
        assert_eq!(hep.src_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(hep.dst_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(hep.src_port, 5060);
        assert_eq!(hep.dst_port, 5061);
        assert_eq!(&hep.payload[..], b"PING");
        // No capture-id chunk present.
        assert_eq!(hep.capture_id, None);
    }

    /// The correlation-id chunk decodes as UTF-8 with trailing NULs
    /// trimmed (senders often NUL-pad the Call-ID).
    #[test]
    fn parse_hep_v3_correlation_id_trims_trailing_nuls() {
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &[10, 0, 0, 2]);
        append_chunk(&mut chunks, 0, CHUNK_CORRELATION_ID, b"call-abc-123\0\0\0");
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, b"X");
        let data = assemble_v3(&chunks);

        let hep = parse_hep(&data).expect("parse should succeed");
        assert_eq!(hep.correlation_id.as_deref(), Some("call-abc-123"));
    }

    /// Invalid UTF-8 in the correlation-id is lossily decoded (never an
    /// error) so a single bad byte can't drop an otherwise-valid packet.
    #[test]
    fn parse_hep_v3_correlation_id_invalid_utf8_is_lossy() {
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &[10, 0, 0, 2]);
        append_chunk(&mut chunks, 0, CHUNK_CORRELATION_ID, &[0xff, 0xfe, b'!']);
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, b"X");
        let data = assemble_v3(&chunks);

        let hep = parse_hep(&data).expect("lossy decode, not an error");
        let cid = hep.correlation_id.expect("correlation id present");
        // U+FFFD replacement char for each invalid byte, then the '!'.
        assert!(cid.ends_with('!'), "got: {cid:?}");
        assert!(cid.contains('\u{fffd}'), "got: {cid:?}");
    }

    /// IPv6 source/destination chunks decode to the right addresses,
    /// exercising the 16-byte address branches directly (not via builder).
    #[test]
    fn parse_hep_v3_ipv6_chunks_decode() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xaa);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xbb);
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_SRC_IPV6, &src.octets());
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV6, &dst.octets());
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, b"Y");
        let data = assemble_v3(&chunks);

        let hep = parse_hep(&data).expect("parse should succeed");
        assert_eq!(hep.src_addr, IpAddr::V6(src));
        assert_eq!(hep.dst_addr, IpAddr::V6(dst));
    }

    /// An empty payload chunk yields an empty payload Vec (not an error),
    /// and an absent payload chunk leaves the payload empty by default.
    #[test]
    fn parse_hep_v3_empty_and_absent_payload() {
        // Empty payload chunk.
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &[10, 0, 0, 2]);
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, b"");
        let data = assemble_v3(&chunks);
        let hep = parse_hep(&data).expect("empty payload is valid");
        assert!(hep.payload.is_empty());

        // No payload chunk at all.
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &[10, 0, 0, 2]);
        let data = assemble_v3(&chunks);
        let hep = parse_hep(&data).expect("absent payload is valid");
        assert!(hep.payload.is_empty());
    }

    /// RTCP and Unknown protocol-type bytes decode correctly through the
    /// parser (covers the non-SIP arms of HepProtocol::from_byte in situ).
    #[test]
    fn parse_hep_v3_rtcp_and_unknown_proto_types() {
        let make = |proto: u8| {
            let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
            make_hep_v3(src, dst, 1, 2, 0, 0, proto, b"Z")
        };
        assert_eq!(parse_hep(&make(5)).unwrap().protocol, HepProtocol::Rtcp);
        assert_eq!(parse_hep(&make(32)).unwrap().protocol, HepProtocol::Rtp);
        assert_eq!(
            parse_hep(&make(200)).unwrap().protocol,
            HepProtocol::Unknown(200)
        );
    }

    /// A chunk header that begins inside `total_length` but whose 6-byte
    /// header does not fully fit before `total_length` ends is silently
    /// left unwalked (loop guard `offset + CHUNK_HEADER_LEN <= total_len`).
    /// The required chunks before it still parse.
    #[test]
    fn parse_hep_v3_trailing_partial_chunk_header_ignored() {
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &[10, 0, 0, 2]);
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, b"OK");
        // Append 3 trailing bytes — not enough for a full chunk header.
        chunks.extend_from_slice(&[0xde, 0xad, 0xbe]);
        let data = assemble_v3(&chunks);

        let hep = parse_hep(&data).expect("partial trailing header is ignored");
        assert_eq!(&hep.payload[..], b"OK");
    }

    // ── Malformed / edge HEP v2 parsing ──────────────────────────────

    /// A HEP v2 header length below the 16-byte IPv4 minimum is rejected
    /// even when enough bytes are present.
    #[test]
    fn parse_hep_v2_header_len_below_minimum() {
        // version=2, header_len=10 (< HEP2_MIN_HEADER), followed by padding.
        let data = [0x02u8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = parse_hep(&data).unwrap_err();
        assert!(
            format!("{err}").contains("below minimum"),
            "expected below-minimum error, got: {err}"
        );
    }

    /// A HEP v2 packet whose header consumes the whole buffer yields an
    /// empty payload (boundary case: `data[header_len..]` is empty).
    #[test]
    fn parse_hep_v2_empty_payload() {
        let data = make_hep_v2(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            100,
            200,
            b"",
        );
        let hep = parse_hep(&data).expect("parse should succeed");
        assert_eq!(hep.version, 2);
        assert!(hep.payload.is_empty());
        assert_eq!(hep.ip_protocol, 17);
        assert_eq!(hep.protocol, HepProtocol::Sip);
        assert_eq!(hep.correlation_id, None);
        assert_eq!(hep.capture_id, None);
    }

    // ── Builder structure & round-trips ──────────────────────────────

    /// `build_hep_v3` must emit the magic, a `total_length` equal to the
    /// real byte count, and (for IPv4) the IPv4 family/address chunk types
    /// rather than the IPv6 variants.
    #[test]
    fn build_hep_v3_header_and_length_consistent() {
        let endpoint = HepEndpoint {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 5060,
            dst_port: 5061,
            transport: TransportProto::Udp,
        };
        let ts = Utc.timestamp_opt(1700000000, 0).single().unwrap();
        let built = build_hep_v3(&endpoint, ts, HepProtocol::Sip, 7, None, b"hello");

        assert_eq!(&built[..4], HEP3_MAGIC);
        let declared = u16::from_be_bytes([built[4], built[5]]) as usize;
        assert_eq!(
            declared,
            built.len(),
            "declared total_length must equal real byte count"
        );

        // IPv4 build path must not emit IPv6 address chunk types.
        let v4_src = CHUNK_SRC_IPV4.to_be_bytes();
        assert!(
            built.windows(2).any(|w| w == v4_src),
            "IPv4 src chunk type should be present"
        );
        let v6_src = CHUNK_SRC_IPV6.to_be_bytes();
        // Search only the chunk region (after the 6-byte header) for the
        // IPv6 type marker; it must be absent for an IPv4 endpoint.
        assert!(
            !built[HEP3_HEADER_LEN..].chunks(2).any(|w| w == v6_src),
            "IPv6 src chunk type must be absent for IPv4 endpoint"
        );
    }

    /// A payload larger than the HEP3 u16 length field is truncated so the
    /// declared total length matches the actual packet size (and stays within
    /// 65535) instead of wrapping into a corrupt header.
    #[test]
    fn build_hep_v3_oversized_payload_does_not_wrap_length() {
        use std::net::IpAddr;
        let endpoint = HepEndpoint {
            src_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            dst_addr: "10.0.0.2".parse::<IpAddr>().unwrap(),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
        };
        let payload = vec![0x41u8; 70_000]; // > u16::MAX
        let pkt = build_hep_v3_bytes(
            &endpoint,
            chrono::Utc::now(),
            HepProtocol::Sip,
            1,
            None,
            &payload,
        );

        let declared = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        assert_eq!(
            declared,
            pkt.len(),
            "declared total_len must match the actual packet size"
        );
        assert!(
            pkt.len() <= u16::MAX as usize,
            "packet must fit the u16 length field"
        );
        // The truncated packet must still parse.
        assert!(parse_hep(&pkt).is_ok(), "truncated HEP packet must parse");
    }

    /// `append_chunk` writes a 6-byte header (vendor, type, length) where
    /// length counts the header plus the data, followed by the data verbatim.
    #[test]
    fn append_chunk_layout() {
        let mut buf = Vec::new();
        append_chunk(&mut buf, 0xabcd, 0x0011, &[0xde, 0xad]);
        assert_eq!(buf.len(), CHUNK_HEADER_LEN + 2);
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0xabcd); // vendor
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 0x0011); // type
        assert_eq!(
            u16::from_be_bytes([buf[4], buf[5]]) as usize,
            CHUNK_HEADER_LEN + 2
        );
        assert_eq!(&buf[6..], &[0xde, 0xad]);
    }

    /// Round-trip an RTCP packet with sub-second timestamp precision and
    /// verify the correlation/capture metadata survives when present.
    #[test]
    fn build_and_parse_round_trip_rtcp_with_usec() {
        let endpoint = HepEndpoint {
            src_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 6)),
            src_port: 40000,
            dst_port: 40001,
            transport: TransportProto::Udp,
        };
        let ts = Utc.timestamp_opt(1234567890, 250_000_000).single().unwrap();
        let payload = &[0x80, 0xc8, 0x00, 0x06]; // RTCP SR header start
        let built = build_hep_v3(&endpoint, ts, HepProtocol::Rtcp, 1000, None, payload);
        let parsed = parse_hep(&built).expect("round-trip");

        assert_eq!(parsed.protocol, HepProtocol::Rtcp);
        assert_eq!(parsed.ip_protocol, 17);
        assert_eq!(parsed.capture_id, Some(1000));
        assert_eq!(&parsed.payload[..], payload);
        assert_eq!(parsed.timestamp.timestamp(), 1234567890);
        assert_eq!(parsed.timestamp.timestamp_subsec_micros(), 250_000);
    }

    /// A crafted TS_USEC far outside the microsecond range must not
    /// overflow the ns conversion; the packet still parses.
    #[test]
    fn parse_hep_v3_huge_ts_usec_does_not_panic() {
        // A crafted HEP packet can carry a TS_USEC far outside [0, 1_000_000).
        // The microsecond→nanosecond conversion (`ts_usec * 1000`) must not
        // overflow u32 (panics in debug / wraps in release); the packet should
        // still parse cleanly.
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let data = make_hep_v3(src, dst, 5060, 5061, 1_700_000_000, u32::MAX, 1, b"hello");
        let hep = parse_hep(&data).expect("packet with garbage ts_usec must still parse");
        assert_eq!(hep.src_addr, src);
    }

    /// The `--count` limit counts packets RECEIVED, not only those forwarded
    /// to the pipeline: a listener whose packets are all dropped (here by the
    /// source allowlist) still stops once `count` datagrams have arrived,
    /// instead of running until the duration limit.
    #[test]
    fn count_limit_counts_received_not_only_forwarded() {
        use std::sync::mpsc;
        // Reserve an ephemeral loopback port, then hand it to the listener so
        // the test knows where to send without scraping logs.
        let probe = UdpSocket::bind("127.0.0.1:0").expect("reserve port");
        let port = probe.local_addr().expect("local_addr").port();
        drop(probe);
        let bind = format!("127.0.0.1:{port}");

        let (tx, rx) = crate::capture::channel::packet_channel(64);
        let config = CaptureConfig {
            count: Some(2),
            // Safety net so a forward-only impl still terminates the thread
            // instead of hanging the test.
            duration: Some(Duration::from_secs(4)),
            ..CaptureConfig::default()
        };
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
        let (done_tx, done_rx) = mpsc::channel();
        let bind_thread = bind.clone();
        std::thread::spawn(move || {
            // Allowlist excludes 127.0.0.1, so every received datagram is
            // dropped before it can be forwarded — yet it must still count.
            let allow = vec![CidrRange::parse("10.0.0.0/8").expect("cidr")];
            let opts = HepListenerOpts {
                allowlist: &allow,
                rate_limit: 1_000_000,
                per_peer_rate_limit: 0,
                max_tracked_peers: crate::rate_limit::DEFAULT_MAX_TRACKED_PEERS,
                auth_key: None,
                auth_mode: HepAuthMode::Plain,
                hmac_window_secs: DEFAULT_HMAC_WINDOW_SECS,
            };
            let r = capture_hep(&bind_thread, &config, tx, &opts, Some(ready_tx));
            let _ = done_tx.send(r.is_ok());
        });

        assert!(
            matches!(ready_rx.recv_timeout(Duration::from_secs(5)), Ok(Ok(()))),
            "listener must report a successful bind"
        );

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let ts = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        let pkt = build_hep_v3(
            &v4_endpoint(),
            ts,
            HepProtocol::Sip,
            1,
            None,
            b"INVITE sip:x SIP/2.0\r\n\r\n",
        );
        for _ in 0..2 {
            sender.send_to(&pkt, &bind).expect("send datagram");
            std::thread::sleep(Duration::from_millis(20));
        }

        // Received-counting: the listener stops promptly after 2 datagrams,
        // well before the 4s duration net.
        let finished = done_rx.recv_timeout(Duration::from_secs(2));
        assert!(
            matches!(finished, Ok(true)),
            "listener must stop after receiving `count` datagrams even when all are dropped"
        );
        // Confirm the drops really happened: nothing reached the pipeline.
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "allowlist drops everything; no packet should reach the pipeline"
        );
    }

    // ── Per-source frame ordinals (SRC1 stage 2) ─────────────────────────
    //
    // `Packet::frame_ref` requires BOTH a source name and an ordinal. The HEP
    // listener stamped only the name, so every fact built from a HEP-delivered
    // message reported no opening frame at all.

    /// Drive the real listener and read back the ordinals it stamped.
    ///
    /// Returns `(source label, ordinal)` per packet that reached the pipeline,
    /// in arrival order. One datagram per entry in `capture_ids`, in order, so
    /// a caller can interleave senders.
    fn hep_ordinals_for(capture_ids: &[u32]) -> Vec<(String, Option<u64>)> {
        use std::sync::mpsc;

        // Reserve an ephemeral loopback port, then hand it to the listener so
        // the test knows where to send without scraping logs.
        let probe = UdpSocket::bind("127.0.0.1:0").expect("reserve port");
        let port = probe.local_addr().expect("local_addr").port();
        drop(probe);
        let bind = format!("127.0.0.1:{port}");

        let (tx, rx) = crate::capture::channel::packet_channel(64);
        let config = CaptureConfig {
            count: Some(capture_ids.len() as u64),
            // Safety net so a listener that never reaches the count still ends
            // its thread instead of hanging the suite.
            duration: Some(Duration::from_secs(8)),
            ..CaptureConfig::default()
        };
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
        let (done_tx, done_rx) = mpsc::channel();
        let bind_thread = bind.clone();
        std::thread::spawn(move || {
            let opts = HepListenerOpts {
                allowlist: &[],
                rate_limit: 1_000_000,
                per_peer_rate_limit: 0,
                max_tracked_peers: crate::rate_limit::DEFAULT_MAX_TRACKED_PEERS,
                auth_key: None,
                auth_mode: HepAuthMode::Plain,
                hmac_window_secs: DEFAULT_HMAC_WINDOW_SECS,
            };
            let r = capture_hep(&bind_thread, &config, tx, &opts, Some(ready_tx));
            let _ = done_tx.send(r.is_ok());
        });

        assert!(
            matches!(ready_rx.recv_timeout(Duration::from_secs(5)), Ok(Ok(()))),
            "listener must report a successful bind"
        );

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let ts = Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .unwrap_or_default();
        for id in capture_ids {
            let pkt = build_hep_v3(
                &v4_endpoint(),
                ts,
                HepProtocol::Sip,
                *id,
                None,
                b"INVITE sip:x SIP/2.0\r\n\r\n",
            );
            sender.send_to(&pkt, &bind).expect("send datagram");
            // Serialised so arrival order is send order: the assertions are
            // about which COUNTER advanced, never about scheduling.
            std::thread::sleep(Duration::from_millis(20));
        }

        let mut got = Vec::new();
        for _ in 0..capture_ids.len() {
            match rx.recv_timeout(Duration::from_secs(3)) {
                Ok(p) => got.push((
                    p.interface.as_deref().unwrap_or("<none>").to_string(),
                    p.origin.map(|o| o.ordinal),
                )),
                Err(e) => panic!("expected {} packets, got {got:?}: {e}", capture_ids.len()),
            }
        }
        let _ = done_rx.recv_timeout(Duration::from_secs(5));
        got
    }

    /// **Ordinals are per source and monotonic.**
    ///
    /// One sender, three datagrams: its frames must be numbered 0, 1, 2 within
    /// its own source name. Without an ordinal `Packet::frame_ref` returns
    /// `None` — it requires both halves — so no fact HEP delivered could name
    /// the datagram it came from.
    #[test]
    fn ordinals_are_per_source_and_monotonic() {
        let got = hep_ordinals_for(&[7, 7, 7]);
        let ordinals: Vec<Option<u64>> = got.iter().map(|(_, o)| *o).collect();
        assert_eq!(
            ordinals,
            vec![Some(0), Some(1), Some(2)],
            "one sender's frames must be numbered 0,1,2 within its own \
             source: {got:?}"
        );
        let labels: std::collections::BTreeSet<&str> =
            got.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            labels.len(),
            1,
            "one capture id from one peer is ONE source: {labels:?}"
        );
    }

    /// **Two members interleaving do not share a counter.**
    ///
    /// A frame's identity is its source plus its position in that source, so
    /// two senders alternating through one listener must each count from zero.
    /// One listener-wide counter would number them 0..5 and hand each source a
    /// sequence full of holes — a pointer naming a position no reader of that
    /// source can find, which is worse than no pointer because it looks like
    /// one.
    #[test]
    fn two_members_interleaving_do_not_share_an_ordinal_counter() {
        let got = hep_ordinals_for(&[7, 9, 7, 9, 7, 9]);
        let mut per_source: std::collections::BTreeMap<&str, Vec<Option<u64>>> =
            std::collections::BTreeMap::new();
        for (label, ord) in &got {
            per_source.entry(label.as_str()).or_default().push(*ord);
        }
        assert_eq!(
            per_source.len(),
            2,
            "two capture ids are two sources: {per_source:?}"
        );
        for (label, ordinals) in &per_source {
            assert_eq!(
                *ordinals,
                vec![Some(0), Some(1), Some(2)],
                "'{label}' must count its OWN frames from zero rather than \
                 share a listener-wide counter: {per_source:?}"
            );
        }
    }

    /// The sender table is bounded, and at the bound it withholds an ordinal
    /// rather than recycling one.
    ///
    /// The label carries a capture-agent id an unauthenticated peer chooses,
    /// so one host can mint unbounded labels. Recycling a counter would give a
    /// source a SECOND frame 0 — two datagrams with one name — so a new sender
    /// past the bound gets nothing, and `frame_ref` then reports unknown,
    /// which is true.
    #[test]
    fn a_new_hep_sender_past_the_bound_gets_no_ordinal_rather_than_a_recycled_one() {
        let mut ord = HepFrameOrdinals::new(2);
        assert_eq!(ord.next_origin("1@10.0.0.1").map(|o| o.ordinal), Some(0));
        assert_eq!(ord.next_origin("2@10.0.0.1").map(|o| o.ordinal), Some(0));
        assert_eq!(
            ord.next_origin("3@10.0.0.1").map(|o| o.ordinal),
            None,
            "a third sender past a bound of two must be left unnumbered"
        );
        // The senders already being counted keep counting: the bound must not
        // turn into a denial of provenance for the nodes that were there
        // first.
        assert_eq!(ord.next_origin("1@10.0.0.1").map(|o| o.ordinal), Some(1));
        assert_eq!(ord.next_origin("2@10.0.0.1").map(|o| o.ordinal), Some(1));
    }

    /// A bare address is a HOST, so `--hep-allow 10.0.0.40` works without the
    /// operator having to know to write `/32`.
    #[test]
    fn a_bare_ipv4_address_is_accepted_as_a_host_route() {
        let r = CidrRange::parse("10.0.0.40").expect("a bare address is a host");
        assert!(r.contains("10.0.0.40".parse().unwrap()), "matches itself");
        assert!(
            !r.contains("10.0.0.41".parse().unwrap()),
            "and nothing else - a bare address must never widen the allowlist"
        );
    }

    #[test]
    fn a_bare_ipv6_address_is_accepted_as_a_host_route() {
        let r = CidrRange::parse("2001:db8::1").expect("a bare v6 address is a host");
        assert!(r.contains("2001:db8::1".parse().unwrap()));
        assert!(!r.contains("2001:db8::2".parse().unwrap()));
    }

    /// The security-relevant case. An address that LOOKS like a classful
    /// network must still be a single host: inferring /8 from `10.0.0.0` would
    /// silently admit sixteen million addresses the operator never named.
    #[test]
    fn a_bare_address_is_never_inferred_as_a_classful_network() {
        let r = CidrRange::parse("10.0.0.0").expect("parses");
        assert!(r.contains("10.0.0.0".parse().unwrap()));
        assert!(
            !r.contains("10.0.0.1".parse().unwrap()),
            "10.0.0.0 is one host, not 10.0.0.0/8"
        );
        assert!(!r.contains("10.255.255.255".parse().unwrap()));
    }

    #[test]
    fn explicit_cidr_still_parses_and_still_bounds() {
        let r = CidrRange::parse("10.0.0.0/8").expect("cidr");
        assert!(r.contains("10.1.2.3".parse().unwrap()));
        assert!(!r.contains("11.0.0.1".parse().unwrap()));
    }

    /// Malformed input must still be refused with a reason, not silently
    /// treated as a host.
    #[test]
    fn malformed_input_is_still_refused() {
        assert!(CidrRange::parse("notanip").is_err(), "not an address");
        assert!(CidrRange::parse("10.0.0.40/").is_err(), "empty prefix");
        assert!(CidrRange::parse("10.0.0.40/33").is_err(), "prefix too long");
        assert!(CidrRange::parse("").is_err(), "empty string");
    }
}
