// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Live media out: each call a `[[vcon.rule]]` with `live_rtp` matches, sent
//! as it is captured to a UDP target the operator named, as RTP.
//!
//! This is the push form of the live audio the REST API serves on its
//! WebSocket, for a consumer such as a local speech-to-text service that
//! ingests RTP. Both read the same decoded audio
//! ([`crate::rtp::live_audio::LiveStream`]) of the same calls
//! ([`crate::output::vcon::live_calls`], which applies `--content-deny-header`).
//!
//! # What goes on the wire
//!
//! - **RTP** ([RFC 3550](https://www.rfc-editor.org/rfc/rfc3550.html)) with
//!   an L16 payload ([RFC 3551 section 4.5.11](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.11)):
//!   16-bit signed samples in network byte order, 16 kHz, mono, 320 samples
//!   (20 ms) a packet; only the last packet of a leg may be shorter. 16 kHz
//!   is the rate wideband speech is carried at and G.722 decodes to; G.711's
//!   8 kHz is interpolated up to it, Opus's 48 kHz down. The payload type is
//!   96, the first dynamic one ([RFC 3551 section 6](https://www.rfc-editor.org/rfc/rfc3551.html#section-6)):
//!   the static L16 types 10 and 11 are 44.1 kHz.
//! - **One stream per leg**: each RTP stream of the call, which is one
//!   direction of its audio, gets an SSRC of its own, a random starting
//!   sequence number and timestamp ([RFC 3550 section 5.1](https://www.rfc-editor.org/rfc/rfc3550.html#section-5.1)), and the marker bit
//!   on its first packet. Every leg goes to the one target, told apart by
//!   SSRC, so a consumer opens one port.
//! - **Control messages**: one JSON object a datagram, to the same target. A
//!   datagram whose first byte is `{` is one, and RTP's first byte is never
//!   that: its version bits make it 0x80 to 0xBF, the range
//!   [RFC 7983 section 7](https://www.rfc-editor.org/rfc/rfc7983.html#section-7)
//!   gives RTP when it shares a port. `start` comes before the call's first
//!   packet, `leg` announces a leg first seen after the start, and `stop`
//!   comes after the call's last packet, with every leg and what was sent.
//!   Each leg object maps the sent SSRC to the captured stream: its SSRC,
//!   source, destination, codec and rate.
//!
//! # What is never sent
//!
//! - Audio sipnab did not decrypt: a leg negotiated as SRTP that no key
//!   decrypted is `withheld`, with the reason, and carries no stream.
//! - A call `--content-deny-header` withholds; one that gains the header
//!   while it is being sent stops at once.
//! - Anything to an address off loopback, unless the rule opts in with
//!   `live_rtp_allow_remote = true`: plain RTP has no encryption and no
//!   authentication, so the audio is readable by anyone on the path.
//!
//! # Pacing
//!
//! Audio is sent as it is captured. A backlog, such as a capture file read
//! faster than real time or a call first matched after it began, goes out at
//! up to [`MAX_PACKETS_PER_PASS`] packets a leg every [`POLL`], ten times
//! real time, so the receiver's socket buffer is not overrun.

use std::collections::{HashSet, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::rtp::live_audio::{LiveStream, call_streams};
use crate::rtp::stream::{RtpStream, StreamKey};
use crate::security::operator_destination::OperatorDestination;
use crate::sip::dsl::FilterExpr;

/// The rule key that names the target.
pub const TARGET_KEY: &str = "live_rtp";
/// The rule key that lets the target be off loopback.
pub const ALLOW_REMOTE_KEY: &str = "live_rtp_allow_remote";
/// How the destination is quoted back to the operator.
const DESTINATION_LABEL: &str = "[[vcon.rule]] live_rtp";
/// The dynamic payload type the L16 stream carries.
pub const PAYLOAD_TYPE: u8 = 96;
/// The sample rate of what is sent, and the RTP clock rate.
pub const RATE: u32 = 16_000;
/// Samples in one 20 ms packet at [`RATE`].
pub const SAMPLES_PER_PACKET: usize = 320;
/// How often the stores are looked at for new audio.
pub const POLL: Duration = Duration::from_millis(20);
/// The most packets one leg sends in one look: 200 ms of audio.
pub const MAX_PACKETS_PER_PASS: usize = 10;

/// Why a call stopped.
const ENDED: &str = "the call ended";
/// The dialog left the store before it ended.
const GONE: &str = "the call is no longer held";
/// The call gained the `--content-deny-header` header.
const DENIED: &str = "the call carries the --content-deny-header header";
/// The input ended with the call still up.
const CAPTURE_ENDED: &str = "the capture ended";
/// sipnab was asked to stop.
const STOPPED: &str = "sipnab stopped";

/// Proof that the operator named the target a live RTP fork sends to.
///
/// Constructible only by [`Self::for_destination`], which needs an
/// [`OperatorDestination`], which nothing the capture supplies can build. It
/// is neither a `TransmitPermit` nor a `HepExportPermit`, and converts into
/// neither: it licenses sending call audio to the operator's target and
/// nothing else.
#[derive(Debug, Clone, Copy)]
pub struct LiveRtpPermit(());

impl LiveRtpPermit {
    /// Grant the fork because `destination` came from the operator's config.
    pub fn for_destination(destination: &OperatorDestination) -> Self {
        // The proof is the argument's type; nothing further to inspect.
        let _ = destination;
        Self(())
    }
}

/// A rule's target, resolved once at startup.
#[derive(Debug, Clone)]
pub struct Target {
    /// What the operator wrote.
    destination: OperatorDestination,
    /// Where it resolved to.
    addr: SocketAddr,
    /// The proof every send is made under.
    permit: LiveRtpPermit,
}

/// Why `rule`'s target `value`, resolving to `addrs`, may not be used, or
/// `None`.
///
/// Every address must be loopback unless `allow_remote`: RTP has no
/// encryption and no authentication, so off loopback the call's audio is
/// readable by anyone on the path, and only the operator can say that path is
/// theirs.
#[must_use]
pub fn remote_refusal(
    rule: &str,
    value: &str,
    addrs: &[SocketAddr],
    allow_remote: bool,
) -> Option<String> {
    (!allow_remote && addrs.iter().any(|a| !a.ip().is_loopback())).then(|| {
        format!(
            "[[vcon.rule]] '{rule}' has {TARGET_KEY} = '{value}', which is not a loopback \
             address. {TARGET_KEY} sends call audio as plain RTP, which has no encryption and \
             no authentication, so anyone on the path can hear it. Set {ALLOW_REMOTE_KEY} = \
             true in the rule to send it there anyway, or name a loopback address such as \
             127.0.0.1:40000"
        )
    })
}

impl Target {
    /// Resolve `rule`'s `live_rtp` value, refusing what cannot be used.
    ///
    /// # Errors
    ///
    /// The value does not resolve to an address, or resolves off loopback
    /// without `allow_remote` ([`remote_refusal`]).
    pub fn resolve(rule: &str, value: &str, allow_remote: bool) -> Result<Self, String> {
        let addrs: Vec<SocketAddr> = value
            .to_socket_addrs()
            .map_err(|e| {
                format!(
                    "[[vcon.rule]] '{rule}' has {TARGET_KEY} = '{value}', which is not a \
                     host:port that resolves: {e}"
                )
            })?
            .collect();
        let Some(addr) = addrs.first().copied() else {
            return Err(format!(
                "[[vcon.rule]] '{rule}' has {TARGET_KEY} = '{value}', which resolves to no address"
            ));
        };
        if let Some(message) = remote_refusal(rule, value, &addrs, allow_remote) {
            return Err(message);
        }
        let destination = OperatorDestination::from_cli_flag(DESTINATION_LABEL, value);
        let permit = LiveRtpPermit::for_destination(&destination);
        Ok(Self {
            destination,
            addr,
            permit,
        })
    }

    /// The target as the operator wrote it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.destination.as_str()
    }
}

/// What to tell the operator when a rule forks a capture FILE's audio.
#[must_use]
pub fn file_notice(rule: &str, target: &Target, paths: &[std::path::PathBuf]) -> Option<String> {
    let first = paths.first()?;
    let name = std::path::Path::new(&crate::capture::archive::source_name(first))
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let files = if paths.len() == 1 {
        format!("a capture FILE ({name})")
    } else {
        format!("{} capture FILES ({name}, ...)", paths.len())
    };
    Some(format!(
        "[[vcon.rule]] '{rule}' {TARGET_KEY} = '{}' sends the decoded audio of every call the \
         rule matches to that address as RTP, and this run is reading {files}. That audio \
         leaves this process as it is read, at up to ten times real time.",
        target.as_str()
    ))
}

/// The socket a rule's packets leave through, and the permit it sends under.
struct Sender {
    /// Connected to the target.
    socket: UdpSocket,
    /// From the target.
    permit: LiveRtpPermit,
}

impl Sender {
    /// A UDP socket connected to `target`. A send waits up to [`POLL`] for
    /// room in the socket buffer: on loopback a datagram counts against the
    /// sender until the receiver reads it, so a receiver a moment behind
    /// would otherwise lose packets that a short wait delivers. A receiver
    /// whose own buffer is full drops the datagram at once, so the wait
    /// cannot grow without bound.
    fn open(target: &Target) -> std::io::Result<Self> {
        let any: SocketAddr = if target.addr.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(any)?;
        socket.connect(target.addr)?;
        socket.set_write_timeout(Some(POLL))?;
        Ok(Self {
            socket,
            permit: target.permit,
        })
    }

    /// Send one datagram; `false` when it did not leave.
    fn transmit(&self, _permit: &LiveRtpPermit, bytes: &[u8]) -> bool {
        self.socket.send(bytes).is_ok()
    }
}

/// The fields of one RTP header that change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Set on a leg's first packet.
    pub marker: bool,
    /// The sequence number.
    pub seq: u16,
    /// The timestamp, in samples at [`RATE`].
    pub ts: u32,
    /// The leg's SSRC.
    pub ssrc: u32,
}

/// One RTP packet: version 2, no padding, extension or CSRC, payload type
/// [`PAYLOAD_TYPE`], and `samples` as L16 in network byte order.
#[must_use]
pub fn rtp_packet(header: Header, samples: &[i16]) -> Vec<u8> {
    let mut p = Vec::with_capacity(12 + samples.len() * 2);
    p.push(0x80);
    p.push(PAYLOAD_TYPE | if header.marker { 0x80 } else { 0 });
    p.extend_from_slice(&header.seq.to_be_bytes());
    p.extend_from_slice(&header.ts.to_be_bytes());
    p.extend_from_slice(&header.ssrc.to_be_bytes());
    for s in samples {
        p.extend_from_slice(&s.to_be_bytes());
    }
    p
}

/// `pcm` at `from_rate`, at [`RATE`].
///
/// Linear interpolation, frame by frame, through the resampler the WAV
/// export uses: 8 kHz doubles, keeping every input sample, and 48 kHz keeps
/// every third.
#[must_use]
pub fn to_wire_rate(pcm: &[i16], from_rate: u32) -> Vec<i16> {
    crate::rtp::audio_export::resample_linear(pcm, from_rate, RATE)
}

/// One leg's samples waiting to be sent, and its place in its RTP stream.
#[derive(Debug)]
pub struct Packetizer {
    /// The next packet's header.
    next: Header,
    /// Samples not yet sent.
    pending: VecDeque<i16>,
    /// Packets sent.
    packets: u64,
    /// Samples sent.
    samples: u64,
}

impl Packetizer {
    /// A stream with this SSRC, starting sequence number and timestamp.
    #[must_use]
    pub fn new(ssrc: u32, seq: u16, ts: u32) -> Self {
        Self {
            next: Header {
                marker: true,
                seq,
                ts,
                ssrc,
            },
            pending: VecDeque::new(),
            packets: 0,
            samples: 0,
        }
    }

    /// Queue samples at [`RATE`].
    pub fn push(&mut self, samples: &[i16]) {
        self.pending.extend(samples.iter().copied());
    }

    /// Whether anything waits to be sent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Up to `max` packets of what waits: whole 20 ms packets, and, with
    /// `flush`, the remainder as a last shorter one.
    pub fn drain(&mut self, max: usize, flush: bool) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < max {
            let n = if self.pending.len() >= SAMPLES_PER_PACKET {
                SAMPLES_PER_PACKET
            } else if flush && !self.pending.is_empty() {
                self.pending.len()
            } else {
                break;
            };
            let samples: Vec<i16> = self.pending.drain(..n).collect();
            out.push(rtp_packet(self.next, &samples));
            self.next.marker = false;
            self.next.seq = self.next.seq.wrapping_add(1);
            // `n` is at most SAMPLES_PER_PACKET.
            self.next.ts = self.next.ts.wrapping_add(n as u32);
            self.packets = self.packets.saturating_add(1);
            self.samples = self.samples.saturating_add(n as u64);
        }
        out
    }

    /// Drop what waits.
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

/// A leg whose audio is being sent.
struct Sending {
    /// Its decoder and place in the stream's retained frames.
    live: LiveStream,
    /// The rate it decodes to.
    from_rate: u32,
    /// Its RTP stream.
    out: Packetizer,
    /// Frames released before they were read.
    missed: u64,
    /// Frames the decoder refused.
    failed: u64,
}

impl Sending {
    /// Decode what `stream` retained since the last look and queue it.
    fn take(&mut self, stream: &RtpStream) {
        let found = self.live.next(stream);
        self.missed = self.missed.saturating_add(found.missed);
        self.failed = self.failed.saturating_add(found.failed);
        for pcm in found.pcm {
            self.out.push(&to_wire_rate(&pcm, self.from_rate));
        }
    }
}

/// What is done with a leg.
enum Status {
    /// Its audio is sent.
    Sending(Box<Sending>),
    /// SRTP no key decrypted: nothing is sent.
    Withheld(String),
    /// A codec sipnab does not decode.
    Skipped(String),
}

/// One leg of a followed call.
struct Leg {
    /// Its place in the call, in [`call_streams`] order.
    index: usize,
    /// The captured stream.
    key: StreamKey,
    /// The captured stream's codec.
    codec: Option<String>,
    /// The captured stream's rate: what it decodes to, or its RTP clock.
    rate: u32,
    /// The captured stream's packets so far.
    packets: u64,
    /// Its packets SRTP left undecrypted so far.
    undecrypted: u64,
    /// What is done with it.
    status: Status,
}

/// The reason a leg negotiated as SRTP sends nothing.
const UNDECRYPTED: &str = "the leg is SRTP and no key decrypted it; sipnab sends no audio it \
                           could not decrypt";

impl Leg {
    /// A leg for `stream`, `index`th in its call, sent as `ssrc` if it can be.
    fn new(index: usize, stream: &RtpStream, random: &mut Random) -> Self {
        let mut leg = Self {
            index,
            key: stream.key.clone(),
            codec: stream.codec.clone(),
            rate: stream.clock_rate,
            packets: stream.packet_count,
            undecrypted: stream.srtp_undecrypted_packets,
            status: Status::Withheld(UNDECRYPTED.to_owned()),
        };
        leg.classify(stream, random);
        leg
    }

    /// Decide what is done with the leg, from what its stream holds now.
    fn classify(&mut self, stream: &RtpStream, random: &mut Random) {
        if stream.srtp && stream.srtp_decrypted_packets == 0 {
            self.status = Status::Withheld(UNDECRYPTED.to_owned());
            return;
        }
        self.status = match LiveStream::new(stream) {
            Ok(live) => {
                let from_rate = live.rate(stream);
                self.rate = from_rate;
                Status::Sending(Box::new(Sending {
                    live,
                    from_rate,
                    out: Packetizer::new(random.ssrc(), random.u16(), random.u32()),
                    missed: 0,
                    failed: 0,
                }))
            }
            Err(e) => Status::Skipped(e.to_string()),
        };
    }

    /// The leg as a control message gives it.
    fn json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "index": self.index,
            "captured": {
                "ssrc": self.key.ssrc,
                "src": self.key.src.to_string(),
                "dst": self.key.dst.to_string(),
                "codec": self.codec,
                "rate": self.rate,
                "packets": self.packets,
            },
            "undecrypted_packets": self.undecrypted,
        });
        let fields = match &self.status {
            Status::Sending(s) => serde_json::json!({
                "status": "sending",
                "ssrc": s.out.next.ssrc,
                "payload_type": PAYLOAD_TYPE,
                "encoding": "L16",
                "rate": RATE,
                "channels": 1,
                "packets": s.out.packets,
                "samples": s.out.samples,
                "missed_frames": s.missed,
                "failed_frames": s.failed,
            }),
            Status::Withheld(reason) => serde_json::json!({"status": "withheld", "reason": reason}),
            Status::Skipped(reason) => serde_json::json!({"status": "skipped", "reason": reason}),
        };
        if let (Some(v), serde_json::Value::Object(f)) = (v.as_object_mut(), fields) {
            v.extend(f);
            // G.729.1 is decoded to its core layer: say so, with the bit
            // rates of the frames decoded so far.
            if let Status::Sending(s) = &self.status
                && let Some(caveat) = s.live.caveat()
            {
                v.insert("decoded_as".to_owned(), caveat.into());
            }
        }
        v
    }

    /// The leg's queued audio, if it is sent.
    fn out(&mut self) -> Option<&mut Packetizer> {
        match &mut self.status {
            Status::Sending(s) => Some(&mut s.out),
            _ => None,
        }
    }
}

/// SSRCs, sequence numbers and timestamps, random as [RFC 3550 section 5.1](https://www.rfc-editor.org/rfc/rfc3550.html#section-5.1)
/// asks, and no SSRC given twice while in use.
struct Random {
    /// The system's generator.
    rng: ring::rand::SystemRandom,
    /// SSRCs given out and not yet returned.
    ssrcs: HashSet<u32>,
}

impl Random {
    /// Four random bytes. A generator that fails falls back to the clock,
    /// which still differs from leg to leg.
    fn bytes(&self) -> [u8; 4] {
        ring::rand::generate::<[u8; 4]>(&self.rng).map_or_else(
            |_| {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.subsec_nanos());
                nanos.to_be_bytes()
            },
            ring::rand::Random::expose,
        )
    }

    /// A random 32-bit value.
    fn u32(&self) -> u32 {
        u32::from_be_bytes(self.bytes())
    }

    /// A random 16-bit value.
    fn u16(&self) -> u16 {
        let b = self.bytes();
        u16::from_be_bytes([b[0], b[1]])
    }

    /// An SSRC no leg holds.
    fn ssrc(&mut self) -> u32 {
        loop {
            let s = self.u32();
            if self.ssrcs.insert(s) {
                return s;
            }
        }
    }
}

/// One call being sent.
struct Call {
    /// The rule it is sent for.
    rule: usize,
    /// Its Call-ID.
    call_id: String,
    /// Its legs, in [`call_streams`] order.
    legs: Vec<Leg>,
    /// Why it is stopping, once it is.
    ending: Option<&'static str>,
}

/// A datagram for a rule's target.
#[derive(Debug, PartialEq, Eq)]
pub struct Datagram {
    /// The index of the rule whose target it goes to.
    pub rule: usize,
    /// What is sent.
    pub bytes: Vec<u8>,
}

/// One rule with a target.
struct Rule {
    /// Its name.
    name: String,
    /// The calls it matches.
    filter: FilterExpr,
    /// Where its datagrams go; `None` when the socket would not open.
    sender: Option<Sender>,
}

/// Every rule's live RTP fork.
pub struct Forwarder {
    /// The rules with a target.
    rules: Vec<Rule>,
    /// The calls being sent.
    calls: Vec<Call>,
    /// Calls stopped, by rule, until their dialog leaves the store, so they
    /// are not started again.
    done: HashSet<(usize, String)>,
    /// SSRCs, sequence numbers and timestamps.
    random: Random,
    /// When the stores were last looked at.
    last: Instant,
    /// Datagrams that did not leave.
    unsent: u64,
}

impl Forwarder {
    /// The fork of every rule in `rules` with a `live_rtp` target, or `None`
    /// when none has one.
    #[must_use]
    pub fn new(rules: &[crate::app::batch::VconRule]) -> Option<Self> {
        let rules: Vec<Rule> = rules
            .iter()
            .filter_map(|r| {
                let target = r.live_rtp.as_ref()?;
                let sender = Sender::open(target)
                    .map_err(|e| {
                        tracing::error!(
                            "[[vcon.rule]] '{}': cannot open a socket to {TARGET_KEY} = '{}': {e}; \
                             no audio is sent there",
                            r.name,
                            target.as_str()
                        );
                    })
                    .ok();
                Some(Rule {
                    name: r.name.clone(),
                    filter: r.filter.clone(),
                    sender,
                })
            })
            .collect();
        (!rules.is_empty()).then(|| Self {
            rules,
            calls: Vec::new(),
            done: HashSet::new(),
            random: Random {
                rng: ring::rand::SystemRandom::new(),
                ssrcs: HashSet::new(),
            },
            last: Instant::now(),
            unsent: 0,
        })
    }

    /// Whether [`POLL`] has passed since the last look; restarts the wait
    /// when it has.
    pub fn due(&mut self) -> bool {
        let due = self.last.elapsed() >= POLL;
        if due {
            self.last = Instant::now();
        }
        due
    }

    /// Whether no call is being sent.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.calls.is_empty()
    }

    /// Datagrams that did not leave, over the run.
    #[must_use]
    pub fn unsent(&self) -> u64 {
        self.unsent
    }

    /// Look at the stores once: start the calls a rule newly matches, queue
    /// what each leg retained since the last look, and give the datagrams to
    /// send. With `input_ended`, a call still up stops once its audio is out.
    pub fn pass(
        &mut self,
        ds: &crate::sip::dialog_store::DialogStore,
        ss: &crate::rtp::stream_store::StreamStore,
        deny_header: Option<&str>,
        input_ended: bool,
    ) -> Vec<Datagram> {
        let mut out = Vec::new();
        self.done.retain(|(_, id)| ds.get(id).is_some());
        for (r, rule) in self.rules.iter().enumerate() {
            for dialog in crate::output::vcon::live_calls([&rule.filter], ds, ss, deny_header) {
                let id = &dialog.call_id;
                if self.done.contains(&(r, id.clone()))
                    || self.calls.iter().any(|c| c.rule == r && c.call_id == *id)
                {
                    continue;
                }
                let mut call = Call {
                    rule: r,
                    call_id: id.clone(),
                    legs: Vec::new(),
                    ending: None,
                };
                for stream in call_streams(ss, id) {
                    let leg = Leg::new(call.legs.len(), stream, &mut self.random);
                    call.legs.push(leg);
                }
                out.push(control(
                    r,
                    &serde_json::json!({
                        "type": "start", "call_id": id, "rule": rule.name,
                        "legs": call.legs.iter().map(Leg::json).collect::<Vec<_>>(),
                    }),
                ));
                self.calls.push(call);
            }
        }
        for call in &mut self.calls {
            let name = &self.rules[call.rule].name;
            if call.ending.is_none() {
                let id = call.call_id.clone();
                for stream in call_streams(ss, &id) {
                    let leg = match call.legs.iter_mut().find(|l| l.key == stream.key) {
                        Some(leg) => {
                            if matches!(leg.status, Status::Withheld(_))
                                && stream.srtp_decrypted_packets > 0
                            {
                                leg.classify(stream, &mut self.random);
                                out.push(leg_message(call.rule, name, &call.call_id, leg));
                            }
                            leg
                        }
                        None => {
                            let leg = Leg::new(call.legs.len(), stream, &mut self.random);
                            out.push(leg_message(call.rule, name, &call.call_id, &leg));
                            call.legs.push(leg);
                            let last = call.legs.len() - 1;
                            &mut call.legs[last]
                        }
                    };
                    leg.packets = stream.packet_count;
                    leg.undecrypted = stream.srtp_undecrypted_packets;
                    if let Status::Sending(s) = &mut leg.status {
                        s.take(stream);
                    }
                }
                call.ending = match ds.get(&call.call_id) {
                    None => Some(GONE),
                    Some(d) if crate::output::vcon::denied_by_header(d, deny_header) => {
                        call.legs
                            .iter_mut()
                            .filter_map(Leg::out)
                            .for_each(Packetizer::clear);
                        Some(DENIED)
                    }
                    Some(d) if d.state().is_final() => Some(ENDED),
                    Some(_) if input_ended => Some(CAPTURE_ENDED),
                    Some(_) => None,
                };
            }
            let flush = call.ending.is_some();
            for leg in &mut call.legs {
                if let Some(p) = leg.out() {
                    out.extend(
                        p.drain(MAX_PACKETS_PER_PASS, flush)
                            .into_iter()
                            .map(|bytes| Datagram {
                                rule: call.rule,
                                bytes,
                            }),
                    );
                }
            }
        }
        self.finish_stopped(&mut out, None);
        out
    }

    /// Stop every call at once, sending nothing more of its audio: sipnab is
    /// stopping.
    pub fn stop_all(&mut self) -> Vec<Datagram> {
        let mut out = Vec::new();
        self.finish_stopped(&mut out, Some(STOPPED));
        out
    }

    /// Send the stop of each call that is stopping and has nothing left to
    /// send, or of every call with `force`, and forget it.
    fn finish_stopped(&mut self, out: &mut Vec<Datagram>, force: Option<&'static str>) {
        let mut kept = Vec::new();
        for mut call in std::mem::take(&mut self.calls) {
            if let Some(reason) = force {
                call.ending = Some(reason);
                call.legs
                    .iter_mut()
                    .filter_map(Leg::out)
                    .for_each(Packetizer::clear);
            }
            let drained = call
                .legs
                .iter_mut()
                .filter_map(Leg::out)
                .all(|p| p.is_empty());
            match call.ending {
                Some(reason) if drained => {
                    out.push(control(
                        call.rule,
                        &serde_json::json!({
                            "type": "stop", "call_id": call.call_id,
                            "rule": self.rules[call.rule].name, "reason": reason,
                            "legs": call.legs.iter().map(Leg::json).collect::<Vec<_>>(),
                        }),
                    ));
                    for leg in &mut call.legs {
                        if let Some(p) = leg.out() {
                            self.random.ssrcs.remove(&p.next.ssrc);
                        }
                    }
                    self.done.insert((call.rule, call.call_id));
                }
                _ => kept.push(call),
            }
        }
        self.calls = kept;
    }

    /// Send `datagrams` to their rules' targets.
    pub fn send(&mut self, datagrams: &[Datagram]) {
        for d in datagrams {
            let sent = self
                .rules
                .get(d.rule)
                .and_then(|r| r.sender.as_ref())
                .is_some_and(|s| s.transmit(&s.permit, &d.bytes));
            if !sent {
                self.unsent = self.unsent.saturating_add(1);
            }
        }
    }
}

/// A control message for rule `rule`'s target.
fn control(rule: usize, v: &serde_json::Value) -> Datagram {
    Datagram {
        rule,
        bytes: v.to_string().into_bytes(),
    }
}

/// The `leg` message announcing `leg` of `call_id`.
fn leg_message(rule: usize, name: &str, call_id: &str, leg: &Leg) -> Datagram {
    control(
        rule,
        &serde_json::json!({
            "type": "leg", "call_id": call_id, "rule": name, "leg": leg.json(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// The header is RTP version 2 with the L16 payload type, the marker
    /// where asked, and the samples big-endian.
    #[test]
    fn a_packet_is_rtp_v2_with_l16_in_network_order() {
        let p = rtp_packet(
            Header {
                marker: true,
                seq: 0x0102,
                ts: 0x0304_0506,
                ssrc: 0x0708_090A,
            },
            &[1, -2, 0x1234],
        );
        assert_eq!(
            p,
            vec![
                0x80,
                0x80 | 96,
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x0A,
                0x00,
                0x01,
                0xFF,
                0xFE,
                0x12,
                0x34
            ]
        );
        assert_eq!(
            rtp_packet(
                Header {
                    marker: false,
                    seq: 0,
                    ts: 0,
                    ssrc: 0
                },
                &[]
            )[1],
            96
        );
    }

    /// Whole 20 ms packets leave first; a remainder only with `flush`; the
    /// sequence steps by one, the timestamp by the samples sent, and the
    /// marker is on the first packet only.
    #[test]
    fn the_packetizer_sends_20_ms_packets_and_a_flushed_remainder() {
        let mut p = Packetizer::new(7, u16::MAX, u32::MAX - 100);
        p.push(&[5; 700]);
        let first = p.drain(10, false);
        assert_eq!(first.len(), 2, "two whole packets, 60 samples wait");
        assert_eq!(first[0][1], 0x80 | 96);
        assert_eq!(first[1][1], 96);
        assert_eq!(&first[0][2..4], &u16::MAX.to_be_bytes());
        assert_eq!(&first[1][2..4], &0u16.to_be_bytes(), "the sequence wraps");
        assert_eq!(
            &first[1][4..8],
            &(u32::MAX - 100).wrapping_add(320).to_be_bytes()
        );
        assert_eq!(first[0].len(), 12 + 640);
        assert!(!p.is_empty());
        let last = p.drain(10, true);
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].len(), 12 + 120);
        assert_eq!(
            &last[0][4..8],
            &(u32::MAX - 100).wrapping_add(640).to_be_bytes()
        );
        assert!(p.is_empty());
        assert_eq!((p.packets, p.samples), (3, 700));
    }

    /// No more than `max` packets leave in one drain.
    #[test]
    fn a_drain_sends_at_most_max_packets() {
        let mut p = Packetizer::new(1, 0, 0);
        p.push(&vec![0; SAMPLES_PER_PACKET * 12]);
        assert_eq!(
            p.drain(MAX_PACKETS_PER_PASS, true).len(),
            MAX_PACKETS_PER_PASS
        );
        assert_eq!(p.drain(MAX_PACKETS_PER_PASS, true).len(), 2);
    }

    /// 8 kHz doubles and keeps every input sample at the even places; 48 kHz
    /// keeps every third; 16 kHz is unchanged.
    #[test]
    fn audio_reaches_16_khz() {
        let pcm: Vec<i16> = (0..160).map(|i| i * 100).collect();
        let up = to_wire_rate(&pcm, 8000);
        assert_eq!(up.len(), 320);
        assert!(pcm.iter().enumerate().all(|(i, s)| up[2 * i] == *s));
        assert_eq!(up[1], 50, "interpolated");
        let wide: Vec<i16> = (0..960).collect();
        let down = to_wire_rate(&wide, 48000);
        assert_eq!(down.len(), 320);
        assert_eq!(down[5], 15);
        assert_eq!(to_wire_rate(&pcm, 16000), pcm);
    }

    /// Loopback is accepted; anything else is refused without the opt-in,
    /// naming both keys, and accepted with it.
    #[test]
    fn an_address_off_loopback_needs_the_opt_in() -> Result<(), TestError> {
        let lo: SocketAddr = "127.0.0.1:40000".parse()?;
        let lo6: SocketAddr = "[::1]:40000".parse()?;
        let remote: SocketAddr = "192.0.2.1:40000".parse()?;
        assert_eq!(remote_refusal("r", "x", &[lo, lo6], false), None);
        let refused = remote_refusal("r", "x", &[lo, remote], false).ok_or("refused")?;
        assert!(refused.contains("live_rtp = 'x'"), "{refused}");
        assert!(refused.contains("live_rtp_allow_remote"), "{refused}");
        assert_eq!(remote_refusal("r", "x", &[remote], true), None);
        assert!(Target::resolve("r", "127.0.0.1:40000", false).is_ok());
        assert!(Target::resolve("r", "192.0.2.1:40000", false).is_err());
        assert!(Target::resolve("r", "192.0.2.1:40000", true).is_ok());
        assert!(Target::resolve("r", "no port", true).is_err());
        Ok(())
    }

    /// SSRCs are not handed out twice while in use.
    #[test]
    fn ssrcs_are_unique_while_in_use() {
        let mut r = Random {
            rng: ring::rand::SystemRandom::new(),
            ssrcs: HashSet::new(),
        };
        let all: HashSet<u32> = (0..1000).map(|_| r.ssrc()).collect();
        assert_eq!(all.len(), 1000);
    }
}
