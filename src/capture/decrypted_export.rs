// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--pcap-export-mode decrypted`: what sipnab decrypted, written as plaintext.
//!
//! Every captured packet goes into a short reorder buffer. What sipnab
//! decrypted comes out rebuilt on its original addresses, ports and capture
//! time: each SIP message from TLS or WSS as one plain TCP frame, each SRTP
//! packet as the RTP packet under it. Everything else comes out exactly as
//! captured. No key material is ever written.
//!
//! The rules, as approved (backlog PCAPX-DEC, 2026-09-29):
//!
//! * D1, order. A record can decrypt after its packet went by, once its keys
//!   arrive. Packets are held for [`reorder_window`] of capture time (the
//!   window the TLS decryptor already holds records for) and at most
//!   [`REORDER_BYTE_CAP`] bytes, and leave in capture order. A frame that
//!   arrives older than what already left is written anyway and counted.
//! * D2, a decrypted TLS connection. Its captured segments, handshake
//!   included, are replaced by the rebuilt frames, which carry sequence
//!   numbers that run on per direction, so a stream reassembler reads the SIP
//!   in order. A connection that never decrypts is written as captured.
//! * D3, WSS. The SIP message is written as plain SIP over TCP; the frame's
//!   comment says it came over WSS.
//! * D4, stop. A stop discards what is held and counts it; the end of an input
//!   writes it all.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};

use super::packet::Packet;

/// The most bytes the reorder buffer holds before it lets the oldest frames go
/// early.
pub const REORDER_BYTE_CAP: usize = 64 * 1024 * 1024;

/// How long a packet waits for a late decryption: the capture time the TLS
/// decryptor holds a record for, so the export waits exactly as long as a
/// late record can still turn up.
pub fn reorder_window() -> chrono::Duration {
    chrono::Duration::seconds(super::REWIND_MAX_AGE_SECS)
}

/// The pcapng section comment on a decrypted export, so whoever opens the
/// file learns what it is: `capinfos` prints it, and Wireshark shows it under
/// Statistics > Capture File Properties.
pub const SECTION_NOTE: &str = "decrypted by sipnab: plaintext SIP (from TLS and WSS) and RTP \
     (from SRTP) rebuilt on the captured addresses, ports and times; everything else as \
     captured; no keys";

/// Write one frame of the export: with its source comment on PCAP-NG, bare
/// on classic pcap, which has nowhere to put one. `native` only, like the
/// writer.
#[cfg(feature = "native")]
pub fn write_frame(writer: &mut super::PcapWriter, frame: &ExportFrame) -> anyhow::Result<()> {
    match frame.source {
        Some(source) => writer.write_labeled(&frame.packet, source.comment()),
        None => writer.write(&frame.packet),
    }
}

/// What a rebuilt frame was decrypted from. Written as its pcapng comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A SIP message from SIP over TLS.
    Tls,
    /// A SIP message from SIP over secure WebSocket.
    Wss,
    /// An RTP packet from SRTP.
    Srtp,
}

impl Source {
    /// The pcapng comment on a frame rebuilt from this source.
    pub fn comment(self) -> &'static str {
        match self {
            Self::Tls => "sipnab: decrypted from TLS",
            Self::Wss => "sipnab: decrypted from WSS",
            Self::Srtp => "sipnab: decrypted from SRTP",
        }
    }
}

/// One frame for the writer, and the source it was rebuilt from (`None` for a
/// frame written as captured).
#[derive(Debug, Clone)]
pub struct ExportFrame {
    /// The frame.
    pub packet: Packet,
    /// Where a rebuilt frame came from.
    pub source: Option<Source>,
}

/// What the export did, for the run's closing line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportCounts {
    /// SIP messages rebuilt from SIP over TLS.
    pub sip_from_tls: u64,
    /// SIP messages rebuilt from SIP over WSS.
    pub sip_from_wss: u64,
    /// RTP packets rebuilt from SRTP.
    pub rtp_from_srtp: u64,
    /// TLS segments written as captured, because their connection never
    /// decrypted.
    pub tls_copied: u64,
    /// Captured segments of decrypted connections, replaced by rebuilt frames.
    pub segments_replaced: u64,
    /// RTCP beside decrypted SRTP, written as captured (sipnab has no SRTCP
    /// decryption).
    pub srtcp_copied: u64,
    /// Decrypted content whose frame could not be rebuilt (a tunnel, an IP
    /// fragment, an IPv6 extension header, or no captured frame to build on).
    pub not_rebuildable: u64,
    /// Frames written older than one already written.
    pub out_of_order: u64,
    /// Frames held at a stop and discarded, not written.
    pub discarded_at_stop: u64,
}

impl ExportCounts {
    /// The run's closing line.
    pub fn summary_line(&self) -> String {
        format!(
            "decrypted export: {} SIP from TLS, {} SIP from WSS, {} RTP from SRTP; \
             {} TLS segments copied as captured, {} captured segments replaced, \
             {} SRTCP copied as captured, {} not rebuildable, {} out of order, \
             {} discarded at stop",
            self.sip_from_tls,
            self.sip_from_wss,
            self.rtp_from_srtp,
            self.tls_copied,
            self.segments_replaced,
            self.srtcp_copied,
            self.not_rebuildable,
            self.out_of_order,
            self.discarded_at_stop,
        )
    }
}

// ── Frame arithmetic ─────────────────────────────────────────────────────

/// IP protocol number of TCP.
const PROTO_TCP: u8 = 6;
/// IP protocol number of UDP.
const PROTO_UDP: u8 = 17;

/// Sum of big-endian 16-bit words, odd byte padded with zero.
fn sum16(data: &[u8]) -> u32 {
    data.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum()
}

/// The one's-complement checksum over `parts` (RFC 1071).
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut s: u32 = parts.iter().map(|p| sum16(p)).sum();
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// The IP header of a captured frame, as far as a rebuild needs it.
#[derive(Debug, Clone, Copy)]
struct IpView {
    /// Offset of the IP header in the frame.
    off: usize,
    /// Its length: IHL for IPv4, 40 for IPv6 (extension headers refused).
    len: usize,
    /// IPv6 rather than IPv4.
    v6: bool,
    /// The transport protocol (IPv4 protocol, IPv6 next header).
    proto: u8,
    /// An IPv4 fragment (more-fragments set, or a non-zero offset).
    fragment: bool,
}

impl IpView {
    /// The outer IP header of `packet`, or `None` when it has none this can
    /// read (a pre-parsed packet, an unknown link type, a short frame).
    fn of(packet: &Packet) -> Option<Self> {
        let off = super::parse::outer_ip_offset(packet)?;
        let d: &[u8] = &packet.data;
        match d.get(off)? >> 4 {
            4 => {
                let len = usize::from(d[off] & 0x0f) * 4;
                if len < 20 || d.len() < off + len {
                    return None;
                }
                let frag = u16::from_be_bytes([d[off + 6], d[off + 7]]);
                Some(Self {
                    off,
                    len,
                    v6: false,
                    proto: d[off + 9],
                    fragment: frag & 0x2000 != 0 || frag & 0x1fff != 0,
                })
            }
            6 if d.len() >= off + 40 => Some(Self {
                off,
                len: 40,
                v6: true,
                // An extension header shows here as a protocol that is
                // neither TCP nor UDP, and is refused like any other.
                proto: d[off + 6],
                fragment: false,
            }),
            _ => None,
        }
    }

    /// The source and destination address bytes of the header in `d`.
    fn addrs<'a>(&self, d: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        if self.v6 {
            (
                &d[self.off + 8..self.off + 24],
                &d[self.off + 24..self.off + 40],
            )
        } else {
            (
                &d[self.off + 12..self.off + 16],
                &d[self.off + 16..self.off + 20],
            )
        }
    }
}

/// `prefix` (the captured link layer), the captured IP header rewritten for a
/// `transport` of `proto`, and `transport`, whose checksum field sits at
/// `csum_at` and is filled in here.
fn assemble(d: &[u8], ip: IpView, proto: u8, mut transport: Vec<u8>, csum_at: usize) -> Vec<u8> {
    let mut header = d[ip.off..ip.off + ip.len].to_vec();
    let (src, dst) = ip.addrs(d);
    let tlen = transport.len();
    let pseudo = if ip.v6 {
        header[4..6].copy_from_slice(&(tlen as u16).to_be_bytes());
        header[6] = proto;
        let mut p = Vec::with_capacity(40);
        p.extend_from_slice(src);
        p.extend_from_slice(dst);
        p.extend_from_slice(&(tlen as u32).to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, proto]);
        p
    } else {
        header[2..4].copy_from_slice(&((ip.len + tlen) as u16).to_be_bytes());
        // Whole, never a fragment: keep only don't-fragment.
        let df = header[6] & 0x40;
        header[6] = df;
        header[7] = 0;
        header[9] = proto;
        header[10..12].copy_from_slice(&[0, 0]);
        let c = checksum(&[&header]);
        header[10..12].copy_from_slice(&c.to_be_bytes());
        let mut p = Vec::with_capacity(12);
        p.extend_from_slice(src);
        p.extend_from_slice(dst);
        p.extend_from_slice(&[0, proto]);
        p.extend_from_slice(&(tlen as u16).to_be_bytes());
        p
    };
    transport[csum_at..csum_at + 2].copy_from_slice(&[0, 0]);
    let mut c = checksum(&[&pseudo, &transport]);
    if c == 0 && proto == PROTO_UDP {
        c = 0xffff; // zero means "no checksum" in UDP
    }
    transport[csum_at..csum_at + 2].copy_from_slice(&c.to_be_bytes());
    let mut frame = d[..ip.off].to_vec();
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&transport);
    frame
}

/// Rebuild a captured UDP frame around a new UDP payload: the captured link
/// layer and IP header, the lengths and checksums recomputed. `None` for a
/// frame that is not a whole UDP datagram this can rebuild: a fragment, an
/// IPv6 extension header, a tunnel's outer header, a pre-parsed (HEP) packet.
pub(crate) fn rebuild_udp(packet: &Packet, payload: &[u8]) -> Option<Vec<u8>> {
    let ip = IpView::of(packet)?;
    if ip.proto != PROTO_UDP || ip.fragment {
        return None;
    }
    let d: &[u8] = &packet.data;
    let ports = d.get(ip.off + ip.len..ip.off + ip.len + 4)?;
    let mut udp = ports.to_vec();
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    Some(assemble(d, ip, PROTO_UDP, udp, 6))
}

/// A synthetic TCP segment carrying `payload`, on the addresses of `template`
/// (a captured packet of this direction), with `ports`, `seq` and `ack`.
fn build_tcp(
    template: &Packet,
    ip: IpView,
    ports: (u16, u16),
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&ports.0.to_be_bytes());
    tcp.extend_from_slice(&ports.1.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    // Data offset 5 (no options), PSH|ACK, window 65535, checksum, urgent 0.
    tcp.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    assemble(&template.data, ip, PROTO_TCP, tcp, 16)
}

// ── The export ───────────────────────────────────────────────────────────

/// A TCP connection, direction-free: the lower endpoint first.
type ConnKey = (SocketAddr, SocketAddr);

/// The direction-free key of the connection between `a` and `b`.
fn conn_key(a: SocketAddr, b: SocketAddr) -> ConnKey {
    if a <= b { (a, b) } else { (b, a) }
}

/// One held frame.
#[derive(Debug)]
struct Entry {
    /// The frame, as captured or rebuilt.
    frame: ExportFrame,
    /// The TCP connection a captured segment belongs to.
    conn: Option<ConnKey>,
    /// A captured segment whose payload is TLS.
    tls: bool,
}

/// One direction of a TCP connection: a captured packet to build frames on,
/// and the next sequence number a rebuilt frame takes.
#[derive(Debug)]
struct Direction {
    /// A captured packet of this direction, whose link layer and IP header
    /// the rebuilt frames reuse.
    template: Packet,
    /// Where the template's IP header is.
    ip: IpView,
    /// The sequence number the next rebuilt frame takes.
    next_seq: Option<u32>,
}

/// The reorder buffer and the per-connection state of one export.
#[derive(Debug)]
pub struct DecryptedExport {
    /// How long a packet waits for a late decryption (D1).
    window: chrono::Duration,
    /// The most bytes held before the oldest leave early (D1).
    byte_cap: usize,
    /// Held frames by capture time, then arrival.
    held: BTreeMap<(DateTime<Utc>, u64), Entry>,
    /// Bytes currently held.
    held_bytes: usize,
    /// Frames held so far, the tiebreak for equal capture times.
    arrivals: u64,
    /// The entry of the packet captured last, for `srtp_decrypted`.
    current: Option<(DateTime<Utc>, u64)>,
    /// The newest capture time seen, which the window runs behind.
    newest: Option<DateTime<Utc>>,
    /// The capture time of the newest frame written.
    last_written: Option<DateTime<Utc>>,
    /// Every TCP direction seen, by (source, destination).
    directions: HashMap<(SocketAddr, SocketAddr), Direction>,
    /// Connections that have decrypted: their captured segments are replaced.
    decrypted: HashSet<ConnKey>,
    /// Sources of RTP that decrypted, so the RTCP beside them is recognized.
    srtp_sources: HashSet<(IpAddr, u16)>,
    /// What the export has done.
    counts: ExportCounts,
}

/// A socket address from raw address bytes (4 or 16) and a port.
fn sock(bytes: &[u8], port: u16) -> Option<SocketAddr> {
    let ip = match bytes.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
        16 => IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

impl DecryptedExport {
    /// An export that holds packets for `window` of capture time and at most
    /// `byte_cap` bytes.
    pub fn new(window: chrono::Duration, byte_cap: usize) -> Self {
        Self {
            window,
            byte_cap,
            held: BTreeMap::new(),
            held_bytes: 0,
            arrivals: 0,
            current: None,
            newest: None,
            last_written: None,
            directions: HashMap::new(),
            decrypted: HashSet::new(),
            srtp_sources: HashSet::new(),
            counts: ExportCounts::default(),
        }
    }

    /// Hold `entry`; returns its key.
    fn hold(&mut self, entry: Entry) -> (DateTime<Utc>, u64) {
        let key = (entry.frame.packet.timestamp, self.arrivals);
        self.arrivals += 1;
        self.held_bytes += entry.frame.packet.data.len();
        self.held.insert(key, entry);
        key
    }

    /// A captured packet, before sipnab processes it.
    pub fn captured(&mut self, packet: &Packet) {
        let ts = packet.timestamp;
        if self.newest.is_none_or(|n| ts > n) {
            self.newest = Some(ts);
        }
        let mut conn = None;
        let mut tls = false;
        if let Some(ip) = IpView::of(packet)
            && ip.proto == PROTO_TCP
            && !ip.fragment
        {
            let d: &[u8] = &packet.data;
            let t = ip.off + ip.len;
            if let Some(h) = d.get(t..t + 20) {
                let (sport, dport) = (
                    u16::from_be_bytes([h[0], h[1]]),
                    u16::from_be_bytes([h[2], h[3]]),
                );
                let seq = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
                let syn = h[13] & 0x02 != 0;
                let (s, dst) = ip.addrs(d);
                if let (Some(src), Some(dst)) = (sock(s, sport), sock(dst, dport)) {
                    let payload = d.get(t + usize::from(h[12] >> 4) * 4..).unwrap_or_default();
                    tls = super::tls::is_tls(payload);
                    conn = Some(conn_key(src, dst));
                    let dir = self
                        .directions
                        .entry((src, dst))
                        .or_insert_with(|| Direction {
                            template: packet.clone(),
                            ip,
                            next_seq: None,
                        });
                    if dir.next_seq.is_none() {
                        dir.next_seq = Some(if syn { seq.wrapping_add(1) } else { seq });
                    }
                }
            }
        }
        let key = self.hold(Entry {
            frame: ExportFrame {
                packet: packet.clone(),
                source: None,
            },
            conn,
            tls,
        });
        self.current = Some(key);
    }

    /// The packet just captured was SRTP that sipnab decrypted; `rtp` is the
    /// RTP packet under it (header and plaintext payload, tag removed).
    pub fn srtp_decrypted(&mut self, rtp: &[u8]) {
        let Some(entry) = self.current.and_then(|k| self.held.get_mut(&k)) else {
            self.counts.not_rebuildable += 1;
            return;
        };
        let packet = &entry.frame.packet;
        let Some(frame) = rebuild_udp(packet, rtp) else {
            self.counts.not_rebuildable += 1;
            return;
        };
        if let Some(ip) = IpView::of(packet) {
            let d: &[u8] = &packet.data;
            let t = ip.off + ip.len;
            if let (Some(p), (s, _)) = (d.get(t..t + 2), ip.addrs(d))
                && let Some(src) = sock(s, u16::from_be_bytes([p[0], p[1]]))
            {
                self.srtp_sources.insert((src.ip(), src.port()));
            }
        }
        self.held_bytes = self.held_bytes + frame.len() - entry.frame.packet.data.len();
        let len = frame.len();
        entry.frame.packet.data = frame.into();
        entry.frame.packet.caplen = len;
        entry.frame.packet.origlen = len;
        entry.frame.packet.origin = None;
        entry.frame.source = Some(Source::Srtp);
        entry.conn = None;
        entry.tls = false;
        self.counts.rtp_from_srtp += 1;
    }

    /// The packet just captured was RTCP from `src`.
    pub fn rtcp_seen(&mut self, src: SocketAddr) {
        let (ip, port) = (src.ip(), src.port());
        // RTCP beside RTP: the same port (rtcp-mux) or the one above it.
        if self.srtp_sources.contains(&(ip, port))
            || port
                .checked_sub(1)
                .is_some_and(|p| self.srtp_sources.contains(&(ip, p)))
        {
            self.counts.srtcp_copied += 1;
        }
    }

    /// A SIP message sipnab decrypted from the TCP connection `src` -> `dst`,
    /// at the capture time of the packet that completed its record.
    pub fn sip_decrypted(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        timestamp: DateTime<Utc>,
        message: &[u8],
        source: Source,
    ) {
        let ack = self
            .directions
            .get(&(dst, src))
            .and_then(|d| d.next_seq)
            .unwrap_or(0);
        let Some(dir) = self.directions.get_mut(&(src, dst)) else {
            self.counts.not_rebuildable += 1;
            return;
        };
        let seq = dir.next_seq.unwrap_or(0);
        dir.next_seq = Some(seq.wrapping_add(message.len() as u32));
        let frame = build_tcp(
            &dir.template,
            dir.ip,
            (src.port(), dst.port()),
            seq,
            ack,
            message,
        );
        let len = frame.len();
        let mut packet = dir.template.clone();
        packet.timestamp = timestamp;
        packet.data = frame.into();
        packet.caplen = len;
        packet.origlen = len;
        packet.origin = None;
        self.decrypted.insert(conn_key(src, dst));
        match source {
            Source::Wss => self.counts.sip_from_wss += 1,
            Source::Tls | Source::Srtp => self.counts.sip_from_tls += 1,
        }
        self.hold(Entry {
            frame: ExportFrame {
                packet,
                source: Some(source),
            },
            conn: None,
            tls: false,
        });
    }

    /// Take the oldest held entry, and decide whether it is written.
    fn release_oldest(&mut self) -> Option<Option<ExportFrame>> {
        let (key, entry) = self.held.pop_first()?;
        self.held_bytes -= entry.frame.packet.data.len();
        if self.current == Some(key) {
            self.current = None;
        }
        if entry.frame.source.is_none() && entry.conn.is_some_and(|c| self.decrypted.contains(&c)) {
            self.counts.segments_replaced += 1;
            return Some(None);
        }
        if entry.tls {
            self.counts.tls_copied += 1;
        }
        let ts = key.0;
        match self.last_written {
            Some(l) if ts < l => self.counts.out_of_order += 1,
            _ => self.last_written = Some(ts),
        }
        Some(Some(entry.frame))
    }

    /// Frames whose wait is over, in capture order: older than the window
    /// behind the newest capture, or pushed out by the byte cap.
    pub fn ready(&mut self) -> Vec<ExportFrame> {
        let mut out = Vec::new();
        let horizon = self.newest.map(|n| n - self.window);
        while let Some((&(ts, _), _)) = self.held.first_key_value() {
            let due = horizon.is_some_and(|h| ts <= h) || self.held_bytes > self.byte_cap;
            if !due {
                break;
            }
            if let Some(Some(frame)) = self.release_oldest() {
                out.push(frame);
            }
        }
        out
    }

    /// The input ended: every held frame, in capture order.
    pub fn finish(&mut self) -> Vec<ExportFrame> {
        let mut out = Vec::new();
        while let Some(released) = self.release_oldest() {
            out.extend(released);
        }
        out
    }

    /// A stop: nothing held is written; it is counted.
    pub fn discard(&mut self) {
        self.counts.discarded_at_stop += self.held.len() as u64;
        self.held.clear();
        self.held_bytes = 0;
        self.current = None;
    }

    /// What the export has done so far.
    pub fn counts(&self) -> &ExportCounts {
        &self.counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    // ── Frames built by hand, and a checksum checker ─────────────────────

    const A4: [u8; 4] = [10, 0, 0, 1];
    const B4: [u8; 4] = [10, 0, 0, 2];

    fn t(ms: i64) -> DateTime<Utc> {
        chrono::DateTime::UNIX_EPOCH + chrono::TimeDelta::milliseconds(1_700_000_000_000 + ms)
    }

    fn sum16(data: &[u8]) -> u32 {
        data.chunks(2)
            .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
            .sum()
    }

    fn fold(mut s: u32) -> u16 {
        while s > 0xffff {
            s = (s & 0xffff) + (s >> 16);
        }
        s as u16
    }

    /// True when the one's-complement sum over `parts` is all ones: how a
    /// receiver checks a header or transport checksum.
    fn verifies(parts: &[&[u8]]) -> bool {
        fold(parts.iter().map(|p| sum16(p)).sum()) == 0xffff
    }

    fn eth(ethertype: u16) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 0xbb, 0x02, 0, 0, 0, 0, 0xaa];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, body_len: usize, frag: u16) -> Vec<u8> {
        let total = (20 + body_len) as u16;
        let mut h = vec![0x45, 0];
        h.extend_from_slice(&total.to_be_bytes());
        h.extend_from_slice(&[0x12, 0x34]);
        h.extend_from_slice(&frag.to_be_bytes());
        h.extend_from_slice(&[64, proto, 0, 0]);
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        let c = !fold(sum16(&h));
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h
    }

    fn udp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = eth(0x0800);
        f.extend(ipv4(src, dst, 17, 8 + payload.len(), 0x4000));
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    fn udp6_frame(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = eth(0x86dd);
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[17, 64]);
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    fn tcp_frame(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut f = eth(0x0800);
        f.extend(ipv4(src, dst, 6, 20 + payload.len(), 0x4000));
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes());
        f.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        f.extend_from_slice(payload);
        f
    }

    fn pkt(ms: i64, frame: Vec<u8>) -> Packet {
        let len = frame.len();
        Packet {
            timestamp: t(ms),
            data: frame.into(),
            caplen: len,
            origlen: len,
            interface: None,
            link_type: 1,
            pre_parsed: None,
            origin: None,
        }
    }

    fn sa(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from(ip), port)
    }

    /// The transport header and payload of an Ethernet+IPv4 frame, and the
    /// IPv4 pseudo-header a checksum covers.
    fn v4_parts(f: &[u8]) -> (&[u8], &[u8], Vec<u8>) {
        let ip = &f[14..34];
        let l4 = &f[34..];
        let mut pseudo = ip[12..20].to_vec();
        pseudo.extend_from_slice(&[0, ip[9]]);
        pseudo.extend_from_slice(&(l4.len() as u16).to_be_bytes());
        (ip, l4, pseudo)
    }

    const RTP_PLAIN: &[u8] = b"\x80\x00\x00\x01\x00\x00\x00\xa0\x12\x34\x56\x78plain-audio";

    fn tls_hello() -> Vec<u8> {
        vec![0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]
    }

    fn tls_app() -> Vec<u8> {
        let mut r = vec![0x17, 0x03, 0x03, 0x00, 0x10];
        r.extend_from_slice(&[0xee; 16]);
        r
    }

    fn export() -> DecryptedExport {
        DecryptedExport::new(reorder_window(), REORDER_BYTE_CAP)
    }

    /// The frames written, as (timestamp, bytes), releasing everything.
    fn written(x: &mut DecryptedExport) -> Vec<(DateTime<Utc>, Vec<u8>, Option<Source>)> {
        x.finish()
            .into_iter()
            .map(|f| (f.packet.timestamp, f.packet.data.to_vec(), f.source))
            .collect()
    }

    fn tcp_payload(f: &[u8]) -> &[u8] {
        let off = 14 + 20 + usize::from(f[46] >> 4) * 4;
        &f[off..]
    }

    fn tcp_seq(f: &[u8]) -> u32 {
        u32::from_be_bytes([f[38], f[39], f[40], f[41]])
    }

    fn tcp_ack(f: &[u8]) -> u32 {
        u32::from_be_bytes([f[42], f[43], f[44], f[45]])
    }

    /// A TLS connection 10.0.0.1:40000 -> 10.0.0.2:5061: SYN, SYN-ACK, both
    /// hellos, one application-data record each way.
    fn tls_connection(x: &mut DecryptedExport) {
        let (c, s) = (40_000u16, 5061u16);
        x.captured(&pkt(0, tcp_frame(A4, B4, c, s, 100, 0x02, b"")));
        x.captured(&pkt(1, tcp_frame(B4, A4, s, c, 900, 0x12, b"")));
        x.captured(&pkt(2, tcp_frame(A4, B4, c, s, 101, 0x18, &tls_hello())));
        x.captured(&pkt(3, tcp_frame(B4, A4, s, c, 901, 0x18, &tls_hello())));
        x.captured(&pkt(4, tcp_frame(A4, B4, c, s, 110, 0x18, &tls_app())));
        x.captured(&pkt(5, tcp_frame(B4, A4, s, c, 910, 0x18, &tls_app())));
    }

    const INVITE: &[u8] = b"INVITE sip:b@10.0.0.2 SIP/2.0\r\nCall-ID: x@y\r\n\r\n";
    const RINGING: &[u8] = b"SIP/2.0 180 Ringing\r\nCall-ID: x@y\r\n\r\n";

    // ── Rebuilding one frame ─────────────────────────────────────────────

    #[test]
    fn a_rebuilt_udp_frame_carries_the_decrypted_rtp() -> Result<(), TestError> {
        let srtp = [RTP_PLAIN, &[0xab; 10][..]].concat();
        let p = pkt(0, udp_frame(A4, B4, 40_000, 50_000, &srtp));
        let f = rebuild_udp(&p, RTP_PLAIN).ok_or("rebuilt")?;
        assert_eq!(
            &f[42..],
            RTP_PLAIN,
            "the payload is the plaintext RTP, tag gone"
        );
        assert_eq!(
            &f[..14],
            &p.data[..14],
            "the link-layer header is the captured one"
        );
        Ok(())
    }

    #[test]
    fn a_rebuilt_udp_frame_states_its_new_length() -> Result<(), TestError> {
        let srtp = [RTP_PLAIN, &[0xab; 10][..]].concat();
        let p = pkt(0, udp_frame(A4, B4, 40_000, 50_000, &srtp));
        let f = rebuild_udp(&p, RTP_PLAIN).ok_or("rebuilt")?;
        let udp_len = u16::from_be_bytes([f[38], f[39]]);
        assert_eq!(usize::from(udp_len), 8 + RTP_PLAIN.len());
        let ip_total = u16::from_be_bytes([f[16], f[17]]);
        assert_eq!(usize::from(ip_total), 20 + 8 + RTP_PLAIN.len());
        assert_eq!(f.len(), 14 + 20 + 8 + RTP_PLAIN.len());
        Ok(())
    }

    #[test]
    fn a_rebuilt_ipv4_udp_frame_has_valid_checksums() -> Result<(), TestError> {
        let p = pkt(
            0,
            udp_frame(A4, B4, 40_000, 50_000, &[RTP_PLAIN, &[1; 10][..]].concat()),
        );
        let f = rebuild_udp(&p, RTP_PLAIN).ok_or("rebuilt")?;
        let (ip, l4, pseudo) = v4_parts(&f);
        assert!(verifies(&[ip]), "IPv4 header checksum");
        assert!(verifies(&[&pseudo, l4]), "UDP checksum");
        assert_ne!(
            &l4[6..8],
            &[0, 0],
            "a UDP checksum is written, not left empty"
        );
        Ok(())
    }

    #[test]
    fn a_rebuilt_ipv6_udp_frame_has_its_length_and_mandatory_checksum() -> Result<(), TestError> {
        let p = pkt(
            0,
            udp6_frame(40_000, 50_000, &[RTP_PLAIN, &[1; 10][..]].concat()),
        );
        let f = rebuild_udp(&p, RTP_PLAIN).ok_or("rebuilt")?;
        let plen = u16::from_be_bytes([f[18], f[19]]);
        assert_eq!(usize::from(plen), 8 + RTP_PLAIN.len());
        let l4 = &f[54..];
        let mut pseudo = f[22..54].to_vec();
        pseudo.extend_from_slice(&(l4.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        assert!(
            verifies(&[&pseudo, l4]),
            "UDP checksum over the IPv6 pseudo-header"
        );
        Ok(())
    }

    #[test]
    fn a_fragment_is_not_rebuilt() -> Result<(), TestError> {
        let mut frame = udp_frame(A4, B4, 40_000, 50_000, &[RTP_PLAIN, &[1; 10][..]].concat());
        frame[20] = 0x20; // more fragments
        assert!(rebuild_udp(&pkt(0, frame), RTP_PLAIN).is_none());
        Ok(())
    }

    // ── SRTP through the export ──────────────────────────────────────────

    #[test]
    fn decrypted_srtp_is_written_as_its_rtp_and_counted() -> Result<(), TestError> {
        let mut x = export();
        x.captured(&pkt(
            0,
            udp_frame(A4, B4, 40_000, 50_000, &[RTP_PLAIN, &[1; 10][..]].concat()),
        ));
        x.srtp_decrypted(RTP_PLAIN);
        let out = written(&mut x);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].1[42..], RTP_PLAIN);
        assert_eq!(out[0].2, Some(Source::Srtp));
        assert_eq!(x.counts().rtp_from_srtp, 1);
        Ok(())
    }

    #[test]
    fn srtp_in_a_fragment_is_written_as_captured_and_counted() -> Result<(), TestError> {
        let mut frame = udp_frame(A4, B4, 40_000, 50_000, &[RTP_PLAIN, &[1; 10][..]].concat());
        frame[20] = 0x20;
        let mut x = export();
        x.captured(&pkt(0, frame.clone()));
        x.srtp_decrypted(RTP_PLAIN);
        let out = written(&mut x);
        assert_eq!(out[0].1, frame, "as captured");
        assert_eq!(x.counts().not_rebuildable, 1);
        assert_eq!(x.counts().rtp_from_srtp, 0);
        Ok(())
    }

    #[test]
    fn rtcp_beside_decrypted_srtp_is_counted_as_srtcp_copied() -> Result<(), TestError> {
        let mut x = export();
        x.captured(&pkt(
            0,
            udp_frame(A4, B4, 40_000, 50_000, &[RTP_PLAIN, &[1; 10][..]].concat()),
        ));
        x.srtp_decrypted(RTP_PLAIN);
        x.captured(&pkt(1, udp_frame(A4, B4, 40_001, 50_001, b"\x80\xc8rtcp")));
        x.rtcp_seen(sa(A4, 40_001));
        x.captured(&pkt(
            2,
            udp_frame([10, 0, 0, 9], B4, 7_001, 50_001, b"\x80\xc8rtcp"),
        ));
        x.rtcp_seen(sa([10, 0, 0, 9], 7_001));
        assert_eq!(
            x.counts().srtcp_copied,
            1,
            "only the RTCP beside decrypted SRTP"
        );
        assert_eq!(
            written(&mut x).len(),
            3,
            "RTCP is still written as captured"
        );
        Ok(())
    }

    // ── TLS: one frame per message, the connection replaced (D2) ─────────

    #[test]
    fn a_decrypted_message_is_one_tcp_frame_holding_exactly_that_message() -> Result<(), TestError>
    {
        let mut x = export();
        tls_connection(&mut x);
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Tls);
        let rebuilt: Vec<_> = written(&mut x)
            .into_iter()
            .filter(|w| w.2.is_some())
            .collect();
        assert_eq!(rebuilt.len(), 1);
        assert_eq!(tcp_payload(&rebuilt[0].1), INVITE);
        assert_eq!(
            rebuilt[0].0,
            t(4),
            "the capture time of the record's packet"
        );
        assert_eq!(&rebuilt[0].1[26..30], &A4, "source address");
        assert_eq!(&rebuilt[0].1[30..34], &B4, "destination address");
        assert_eq!(
            u16::from_be_bytes([rebuilt[0].1[34], rebuilt[0].1[35]]),
            40_000
        );
        assert_eq!(
            u16::from_be_bytes([rebuilt[0].1[36], rebuilt[0].1[37]]),
            5061
        );
        Ok(())
    }

    #[test]
    fn rebuilt_tcp_frames_have_valid_checksums() -> Result<(), TestError> {
        let mut x = export();
        tls_connection(&mut x);
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Tls);
        let out = written(&mut x);
        let f = &out.iter().find(|w| w.2.is_some()).ok_or("rebuilt")?.1;
        let (ip, l4, pseudo) = v4_parts(f);
        assert!(verifies(&[ip]), "IPv4 header checksum");
        assert!(verifies(&[&pseudo, l4]), "TCP checksum");
        Ok(())
    }

    #[test]
    fn sequence_numbers_run_on_per_direction() -> Result<(), TestError> {
        let mut x = export();
        tls_connection(&mut x);
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Tls);
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Tls);
        let out: Vec<_> = written(&mut x)
            .into_iter()
            .filter(|w| w.2.is_some())
            .collect();
        assert_eq!(
            tcp_seq(&out[0].1),
            101,
            "the client's first byte after its SYN"
        );
        assert_eq!(
            tcp_seq(&out[1].1),
            101 + INVITE.len() as u32,
            "the next frame starts where the last one ended"
        );
        Ok(())
    }

    #[test]
    fn the_ack_is_the_other_directions_next_sequence() -> Result<(), TestError> {
        let mut x = export();
        tls_connection(&mut x);
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Tls);
        x.sip_decrypted(sa(B4, 5061), sa(A4, 40_000), t(5), RINGING, Source::Tls);
        let out: Vec<_> = written(&mut x)
            .into_iter()
            .filter(|w| w.2.is_some())
            .collect();
        assert_eq!(
            tcp_seq(&out[1].1),
            901,
            "the server's first byte after its SYN-ACK"
        );
        assert_eq!(tcp_ack(&out[1].1), 101 + INVITE.len() as u32);
        assert_eq!(tcp_ack(&out[0].1), 901);
        Ok(())
    }

    #[test]
    fn a_decrypted_connections_captured_segments_are_replaced_and_counted() -> Result<(), TestError>
    {
        let mut x = export();
        tls_connection(&mut x);
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Tls);
        let out = written(&mut x);
        assert_eq!(
            out.len(),
            1,
            "only the rebuilt frame: SYN, hellos and records replaced"
        );
        assert_eq!(x.counts().segments_replaced, 6);
        assert_eq!(x.counts().sip_from_tls, 1);
        Ok(())
    }

    #[test]
    fn a_connection_that_never_decrypts_is_written_as_captured_and_counted() -> Result<(), TestError>
    {
        let mut x = export();
        tls_connection(&mut x);
        let out = written(&mut x);
        assert_eq!(out.len(), 6);
        assert!(out.iter().all(|w| w.2.is_none()));
        assert_eq!(
            x.counts().tls_copied,
            4,
            "the four segments that carried TLS"
        );
        assert_eq!(x.counts().segments_replaced, 0);
        Ok(())
    }

    #[test]
    fn traffic_that_was_never_encrypted_is_written_byte_for_byte() -> Result<(), TestError> {
        let mut x = export();
        let frames = [
            udp_frame(A4, B4, 5060, 5060, INVITE),
            tcp_frame(A4, B4, 40_000, 5060, 1, 0x18, RINGING),
        ];
        for (i, f) in frames.iter().enumerate() {
            x.captured(&pkt(i as i64, f.clone()));
        }
        let out = written(&mut x);
        assert_eq!(
            out.iter().map(|w| w.1.clone()).collect::<Vec<_>>(),
            frames.to_vec()
        );
        assert_eq!(x.counts(), &ExportCounts::default());
        Ok(())
    }

    #[test]
    fn a_message_whose_connection_was_never_captured_is_counted_not_rebuilt()
    -> Result<(), TestError> {
        let mut x = export();
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Tls);
        assert!(written(&mut x).is_empty());
        assert_eq!(x.counts().not_rebuildable, 1);
        Ok(())
    }

    // ── WSS (D3) and frame comments ──────────────────────────────────────

    #[test]
    fn a_wss_message_is_written_as_plain_sip_and_says_wss() -> Result<(), TestError> {
        let mut x = export();
        tls_connection(&mut x);
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Wss);
        let out: Vec<_> = written(&mut x)
            .into_iter()
            .filter(|w| w.2.is_some())
            .collect();
        assert_eq!(tcp_payload(&out[0].1), INVITE, "no WebSocket framing");
        assert_eq!(out[0].2, Some(Source::Wss));
        assert_eq!(x.counts().sip_from_wss, 1);
        Ok(())
    }

    #[test]
    fn each_source_has_its_own_comment() -> Result<(), TestError> {
        let c = [
            Source::Tls.comment(),
            Source::Wss.comment(),
            Source::Srtp.comment(),
        ];
        assert!(
            c[0].contains("TLS") && c[1].contains("WSS") && c[2].contains("SRTP"),
            "{c:?}"
        );
        assert!(
            c.iter().all(|s| s.starts_with("sipnab: decrypted")),
            "{c:?}"
        );
        Ok(())
    }

    // ── Order (D1) ───────────────────────────────────────────────────────

    #[test]
    fn nothing_leaves_before_its_window_has_passed() -> Result<(), TestError> {
        let mut x = export();
        x.captured(&pkt(0, udp_frame(A4, B4, 5060, 5060, INVITE)));
        x.captured(&pkt(4_000, udp_frame(A4, B4, 5060, 5060, INVITE)));
        assert!(x.ready().is_empty(), "4 s is inside the 5 s window");
        x.captured(&pkt(5_001, udp_frame(A4, B4, 5060, 5060, INVITE)));
        let out = x.ready();
        assert_eq!(out.len(), 1, "only the frame the window has passed");
        assert_eq!(out[0].packet.timestamp, t(0));
        Ok(())
    }

    #[test]
    fn a_late_decryption_inside_the_window_lands_in_capture_order() -> Result<(), TestError> {
        let mut x = export();
        tls_connection(&mut x);
        x.captured(&pkt(3_000, udp_frame(A4, B4, 5060, 5060, RINGING)));
        // The keys arrive 3 s later; the record's packet was at 4 ms.
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Tls);
        let out = written(&mut x);
        assert_eq!(
            out.iter().map(|w| w.0).collect::<Vec<_>>(),
            vec![t(4), t(3_000)]
        );
        assert_eq!(x.counts().out_of_order, 0);
        Ok(())
    }

    #[test]
    fn a_late_decryption_beyond_the_window_is_written_out_of_order_and_counted()
    -> Result<(), TestError> {
        let mut x = export();
        tls_connection(&mut x);
        x.captured(&pkt(9_000, udp_frame(A4, B4, 5060, 5060, RINGING)));
        let early = x.ready();
        assert_eq!(
            early.len(),
            6,
            "the connection left, as captured, before any key"
        );
        x.sip_decrypted(sa(A4, 40_000), sa(B4, 5061), t(4), INVITE, Source::Tls);
        let rest = written(&mut x);
        assert_eq!(rest[0].0, t(4));
        assert_eq!(x.counts().out_of_order, 1);
        Ok(())
    }

    #[test]
    fn the_byte_cap_lets_the_oldest_frames_go_early() -> Result<(), TestError> {
        let mut x = DecryptedExport::new(reorder_window(), 200);
        for ms in 0..4 {
            x.captured(&pkt(ms, udp_frame(A4, B4, 5060, 5060, INVITE)));
        }
        let out = x.ready();
        assert!(
            !out.is_empty(),
            "over the cap, the oldest leave before the window"
        );
        assert_eq!(out[0].packet.timestamp, t(0));
        Ok(())
    }

    // ── The end of a run (D4) ────────────────────────────────────────────

    #[test]
    fn the_end_of_an_input_writes_everything_held_in_capture_order() -> Result<(), TestError> {
        let mut x = export();
        for ms in [0, 1, 2] {
            x.captured(&pkt(ms, udp_frame(A4, B4, 5060, 5060, INVITE)));
        }
        let out = written(&mut x);
        assert_eq!(
            out.iter().map(|w| w.0).collect::<Vec<_>>(),
            vec![t(0), t(1), t(2)]
        );
        assert!(x.finish().is_empty(), "nothing is written twice");
        Ok(())
    }

    #[test]
    fn a_stop_writes_nothing_held_and_counts_it() -> Result<(), TestError> {
        let mut x = export();
        for ms in [0, 1, 2] {
            x.captured(&pkt(ms, udp_frame(A4, B4, 5060, 5060, INVITE)));
        }
        x.discard();
        assert_eq!(x.counts().discarded_at_stop, 3);
        assert!(
            x.finish().is_empty(),
            "discarded frames never reach the writer"
        );
        Ok(())
    }

    // ── The closing line ─────────────────────────────────────────────────

    #[test]
    fn the_summary_line_names_every_count() -> Result<(), TestError> {
        let c = ExportCounts {
            sip_from_tls: 1,
            sip_from_wss: 2,
            rtp_from_srtp: 3,
            tls_copied: 4,
            segments_replaced: 5,
            srtcp_copied: 6,
            not_rebuildable: 7,
            out_of_order: 8,
            discarded_at_stop: 9,
        };
        let line = c.summary_line();
        for part in [
            "1 SIP from TLS",
            "2 SIP from WSS",
            "3 RTP from SRTP",
            "4 TLS segments copied as captured",
            "5 captured segments replaced",
            "6 SRTCP copied as captured",
            "7 not rebuildable",
            "8 out of order",
            "9 discarded at stop",
        ] {
            assert!(line.contains(part), "missing {part:?} in {line:?}");
        }
        Ok(())
    }
}
