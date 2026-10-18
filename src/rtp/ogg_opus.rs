// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Ogg Opus: a call's decoded audio as an `audio/ogg` file.
//!
//! The format a `[[vcon.rule]]` with `audio_format = "opus"` writes in place
//! of the WAV. [draft-ietf-vcon-vcon-core-04 section 4.3.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.8)
//! lists `audio/ogg` among the media types a Dialog Object SHOULD use.
//!
//! - The codec is Opus ([RFC 6716](https://www.rfc-editor.org/rfc/rfc6716.html)),
//!   encoded by libopus, which the `opus` feature builds from vendored source.
//! - The file is an Ogg Opus stream ([RFC 7845](https://www.rfc-editor.org/rfc/rfc7845.html)):
//!   an `OpusHead` page, an `OpusTags` page, then the audio pages.
//! - The input is the PCM sipnab already decoded for the WAV, so the two
//!   formats hold the same audio. The provenance note the WAV carries in its
//!   `ICMT` chunk travels here as the `DESCRIPTION` comment.
//!
//! The bitrate is [`BITRATE_PER_CHANNEL`], constant. See its documentation
//! for why that value and why constant.

use anyhow::{Context as _, Result, bail};

/// The Opus bitrate per channel, in bits per second: 24 kbit/s.
///
/// [RFC 7587 section 3.1.1](https://www.rfc-editor.org/rfc/rfc7587.html#section-3.1.1)
/// gives the bitrate "sweet spots" for 20 ms frames: 8-12 kbit/s for
/// narrowband speech and 16-20 kbit/s for wideband speech.
///
/// - 24 kbit/s is above both. A G.711 call (narrowband) and a G.722 call
///   (wideband) are each encoded above the range RFC 7587 recommends for
///   them.
/// - A recording is evidence of what was heard, so it is encoded above the
///   sweet spot rather than at its bottom.
/// - A two-way call is two channels, so 48 kbit/s in all: 6000 bytes a
///   second, against 32000 for the same call as 16-bit WAV at 8 kHz.
///
/// Constant (CBR), not variable. [RFC 7587 section 3.1.2](https://www.rfc-editor.org/rfc/rfc7587.html#section-3.1.2)
/// names the reason that applies here: a variable bitrate can leak what was
/// said through packet sizes when the stream is encrypted, and a rule with
/// `encrypt_to` encrypts this file. Constant also makes the inline budget
/// exact: every second costs the same number of bytes.
pub const BITRATE_PER_CHANNEL: i32 = 24_000;

/// The rates libopus encodes at. Any other input rate is resampled to 48 kHz
/// first.
const OPUS_RATES: [u32; 5] = [8_000, 12_000, 16_000, 24_000, 48_000];

/// The rate every Ogg Opus granule position counts in ([RFC 7845 section 4](https://www.rfc-editor.org/rfc/rfc7845.html#section-4)).
const GRANULE_RATE: u32 = 48_000;

/// Frames of 20 ms: 50 a second.
const FRAMES_PER_SECOND: u32 = 50;

/// Audio packets per Ogg page: one second.
const PACKETS_PER_PAGE: usize = 50;

/// The largest Opus packet libopus writes ([RFC 6716 section 3.4](https://www.rfc-editor.org/rfc/rfc6716.html#section-3.4), R4).
const MAX_PACKET: usize = 1275;

/// `audio`'s PCM as an Ogg Opus file.
///
/// # Errors
///
/// When the WAV in `audio` is not 16-bit PCM, when it holds more than two
/// channels, or when libopus refuses the input.
pub fn encode_dialog_audio(audio: &crate::rtp::audio_export::DialogAudio) -> Result<Vec<u8>> {
    let samples = crate::rtp::wav::pcm_samples(&audio.wav)
        .context("the decoded audio is not a 16-bit PCM WAV")?;
    encode(
        &samples,
        audio.sample_rate,
        audio.channels,
        Some(&audio.note),
    )
}

/// Interleaved 16-bit `samples` at `sample_rate` as an Ogg Opus file, with
/// `comment` as its `DESCRIPTION`.
///
/// # Errors
///
/// When `channels` is not 1 or 2, `sample_rate` is zero, or libopus refuses
/// the input.
pub fn encode(
    samples: &[i16],
    sample_rate: u32,
    channels: u16,
    comment: Option<&str>,
) -> Result<Vec<u8>> {
    let layout = match channels {
        1 => opus::Channels::Mono,
        2 => opus::Channels::Stereo,
        n => bail!("an Ogg Opus recording holds one or two channels, not {n}"),
    };
    if sample_rate == 0 {
        bail!("the audio has a sample rate of zero");
    }
    let width = usize::from(channels);
    let (pcm, rate): (std::borrow::Cow<'_, [i16]>, u32) = if OPUS_RATES.contains(&sample_rate) {
        (samples.into(), sample_rate)
    } else {
        (
            resample(samples, width, sample_rate, GRANULE_RATE).into(),
            GRANULE_RATE,
        )
    };
    let per_channel = pcm.len() / width;
    if per_channel == 0 {
        bail!("the audio holds no samples");
    }
    let libopus = |e: opus::Error| anyhow::anyhow!("libopus: {e}");
    let mut encoder = opus::Encoder::new(rate, layout, opus::Application::Voip).map_err(libopus)?;
    encoder
        .set_bitrate(opus::Bitrate::Bits(
            BITRATE_PER_CHANNEL * i32::from(channels),
        ))
        .map_err(libopus)?;
    encoder.set_vbr(false).map_err(libopus)?;
    // Every rate in OPUS_RATES divides 48 kHz, so the scale is exact.
    let scale = GRANULE_RATE / rate;
    let lookahead = usize::try_from(encoder.get_lookahead().map_err(libopus)?)
        .context("libopus reported a negative lookahead")?;
    let pre_skip = u16::try_from(lookahead * scale as usize)
        .context("the encoder lookahead does not fit the ID header")?;

    let mut stream = OggStream::new(crc32(&pcm_bytes(&pcm)));
    stream.packet(&id_header(channels, pre_skip, sample_rate), 0);
    stream.page(false);
    stream.packet(&comment_header(comment), 0);
    stream.page(false);

    // Enough frames to push the last input sample through the lookahead.
    let frame = (rate / FRAMES_PER_SECOND) as usize;
    let frames = (per_channel + lookahead).div_ceil(frame);
    // RFC 7845 section 4.4: the last page's granule position trims the
    // padding, so a player stops at the input's own last sample.
    let end = i64::from(pre_skip) + i64::try_from(per_channel * scale as usize)?;
    let mut input = vec![0_i16; frame * width];
    let mut packet = vec![0_u8; MAX_PACKET];
    for i in 0..frames {
        input.fill(0);
        let from = (i * frame * width).min(pcm.len());
        let to = ((i + 1) * frame * width).min(pcm.len());
        input[..to - from].copy_from_slice(&pcm[from..to]);
        let size = encoder.encode(&input, &mut packet).map_err(libopus)?;
        let granule = if i + 1 == frames {
            end
        } else {
            // RFC 7845 section 4: every sample decoded so far, pre-skip
            // included.
            i64::try_from((i + 1) * frame * scale as usize)?
        };
        stream.packet(&packet[..size], granule);
        if i + 1 == frames {
            stream.page(true);
        } else if (i + 1) % PACKETS_PER_PAGE == 0 {
            stream.page(false);
        }
    }
    Ok(stream.out)
}

/// The ID header, [RFC 7845 section 5.1](https://www.rfc-editor.org/rfc/rfc7845.html#section-5.1), channel mapping family 0.
fn id_header(channels: u16, pre_skip: u16, input_rate: u32) -> Vec<u8> {
    let mut out = b"OpusHead".to_vec();
    out.push(1); // version
    out.extend_from_slice(&channels.to_le_bytes()[..1]);
    out.extend_from_slice(&pre_skip.to_le_bytes());
    out.extend_from_slice(&input_rate.to_le_bytes());
    out.extend_from_slice(&0_i16.to_le_bytes()); // output gain
    out.push(0); // mapping family: mono or stereo, no table
    out
}

/// The comment header, [RFC 7845 section 5.2](https://www.rfc-editor.org/rfc/rfc7845.html#section-5.2): libopus's version as the
/// vendor, and `comment` as the one `DESCRIPTION` comment.
fn comment_header(comment: Option<&str>) -> Vec<u8> {
    let mut out = b"OpusTags".to_vec();
    let vendor = opus::version();
    push_string(&mut out, vendor);
    match comment {
        Some(text) => {
            out.extend_from_slice(&1_u32.to_le_bytes());
            push_string(&mut out, &format!("DESCRIPTION={text}"));
        }
        None => out.extend_from_slice(&0_u32.to_le_bytes()),
    }
    out
}

/// A 32-bit little-endian length, then the text.
fn push_string(out: &mut Vec<u8>, text: &str) {
    // A provenance note is a few hundred bytes; u32::MAX is not reachable.
    let len = u32::try_from(text.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(text.as_bytes());
}

/// The samples as little-endian bytes, for the stream's serial number.
fn pcm_bytes(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().flat_map(|s| s.to_le_bytes()).collect()
}

/// `samples`, interleaved over `width` channels at `from` Hz, at `to` Hz by
/// linear interpolation.
fn resample(samples: &[i16], width: usize, from: u32, to: u32) -> Vec<i16> {
    let frames = samples.len() / width;
    let out_frames = (frames as u64 * u64::from(to)).div_ceil(u64::from(from)) as usize;
    let step = f64::from(from) / f64::from(to);
    let mut out = Vec::with_capacity(out_frames * width);
    for j in 0..out_frames {
        let position = j as f64 * step;
        let i = position.floor() as usize;
        let frac = position - position.floor();
        for c in 0..width {
            let a = f64::from(samples[(i.min(frames - 1)) * width + c]);
            let b = f64::from(samples[((i + 1).min(frames - 1)) * width + c]);
            out.push((a + (b - a) * frac).round() as i16);
        }
    }
    out
}

/// An Ogg logical bitstream being written (RFC 3533).
struct OggStream {
    /// The stream's serial number.
    serial: u32,
    /// The next page's sequence number.
    sequence: u32,
    /// The pages written so far.
    out: Vec<u8>,
    /// The current page's segment table.
    lacing: Vec<u8>,
    /// The current page's body.
    body: Vec<u8>,
    /// The granule position of the last packet completed on the current
    /// page; -1 when none has.
    granule: i64,
    /// Whether the current page begins inside a packet.
    continued: bool,
}

impl OggStream {
    /// An empty stream with serial number `serial`.
    fn new(serial: u32) -> Self {
        Self {
            serial,
            sequence: 0,
            out: Vec::new(),
            lacing: Vec::new(),
            body: Vec::new(),
            granule: -1,
            continued: false,
        }
    }

    /// Append `data` as one packet ending at `granule`, starting new pages
    /// as the segment table fills.
    fn packet(&mut self, data: &[u8], granule: i64) {
        let mut rest = data;
        let mut first = true;
        loop {
            if self.lacing.len() == 255 {
                self.page(false);
                self.continued = !first;
            }
            first = false;
            let take = rest.len().min(255);
            // `take` is at most 255.
            self.lacing.push(u8::try_from(take).unwrap_or(u8::MAX));
            self.body.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if take < 255 {
                break;
            }
        }
        self.granule = granule;
    }

    /// Write the current page; `eos` marks it the last.
    fn page(&mut self, eos: bool) {
        let mut flags = 0_u8;
        if self.continued {
            flags |= 0x01;
        }
        if self.sequence == 0 {
            flags |= 0x02;
        }
        if eos {
            flags |= 0x04;
        }
        let start = self.out.len();
        self.out.extend_from_slice(b"OggS");
        self.out.push(0); // version
        self.out.push(flags);
        self.out.extend_from_slice(&self.granule.to_le_bytes());
        self.out.extend_from_slice(&self.serial.to_le_bytes());
        self.out.extend_from_slice(&self.sequence.to_le_bytes());
        self.out.extend_from_slice(&[0; 4]); // CRC, filled below
        // At most 255 entries: `packet` starts a page before a 256th.
        self.out
            .push(u8::try_from(self.lacing.len()).unwrap_or(u8::MAX));
        self.out.extend_from_slice(&self.lacing);
        self.out.extend_from_slice(&self.body);
        let crc = crc32(&self.out[start..]);
        self.out[start + 22..start + 26].copy_from_slice(&crc.to_le_bytes());
        self.lacing.clear();
        self.body.clear();
        self.granule = -1;
        self.continued = false;
        self.sequence += 1;
    }
}

/// The Ogg page checksum.
///
/// [RFC 3533 section 6](https://www.rfc-editor.org/rfc/rfc3533.html#section-6):
/// polynomial 0x04c11db7, initial value zero, no reflection, no final XOR,
/// over the whole page with the checksum field zeroed.
fn crc32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0_u32, |crc, &b| {
        let mut c = crc ^ (u32::from(b) << 24);
        for _ in 0..8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0x04c1_1db7
            } else {
                c << 1
            };
        }
        c
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// One Ogg page, as read back.
    #[derive(Debug)]
    struct Page {
        header_type: u8,
        granule: i64,
        serial: u32,
        sequence: u32,
        lacing: Vec<u8>,
        body: Vec<u8>,
    }

    /// Every page of `bytes`, each CRC checked.
    fn pages(bytes: &[u8]) -> Result<Vec<Page>, TestError> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let head = bytes.get(at..at + 27).ok_or("a truncated page header")?;
            if &head[..4] != b"OggS" {
                return Err(format!("no capture pattern at {at}").into());
            }
            let count = usize::from(head[26]);
            let lacing = bytes
                .get(at + 27..at + 27 + count)
                .ok_or("lacing")?
                .to_vec();
            let size: usize = lacing.iter().map(|&l| usize::from(l)).sum();
            let end = at + 27 + count + size;
            let page = bytes.get(at..end).ok_or("a truncated page body")?;
            let mut zeroed = page.to_vec();
            zeroed[22..26].copy_from_slice(&[0; 4]);
            let stored = u32::from_le_bytes(page[22..26].try_into()?);
            if crc32(&zeroed) != stored {
                return Err(format!("page at {at}: the CRC does not match").into());
            }
            out.push(Page {
                header_type: head[5],
                granule: i64::from_le_bytes(head[6..14].try_into()?),
                serial: u32::from_le_bytes(head[14..18].try_into()?),
                sequence: u32::from_le_bytes(head[18..22].try_into()?),
                lacing,
                body: page[27 + count..].to_vec(),
            });
            at = end;
        }
        Ok(out)
    }

    /// The packets of `pages`, reassembled across page boundaries.
    fn packets(pages: &[Page]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut current = Vec::new();
        for page in pages {
            let mut at = 0;
            for &l in &page.lacing {
                current.extend_from_slice(&page.body[at..at + usize::from(l)]);
                at += usize::from(l);
                if l < 255 {
                    out.push(std::mem::take(&mut current));
                }
            }
        }
        out
    }

    /// A tone of `hz` at `rate`, `secs` long.
    fn tone(hz: f64, rate: u32, secs: f64) -> Vec<i16> {
        let n = (f64::from(rate) * secs) as usize;
        (0..n)
            .map(|i| {
                let t = i as f64 / f64::from(rate);
                (8000.0 * (2.0 * std::f64::consts::PI * hz * t).sin()) as i16
            })
            .collect()
    }

    /// Interleave two equal-length channels.
    fn stereo(left: &[i16], right: &[i16]) -> Vec<i16> {
        left.iter().zip(right).flat_map(|(&l, &r)| [l, r]).collect()
    }

    /// The power of `hz` in `samples` at `rate` (Goertzel).
    fn power(samples: &[f64], rate: f64, hz: f64) -> f64 {
        let w = 2.0 * std::f64::consts::PI * hz / rate;
        let coeff = 2.0 * w.cos();
        let (mut s1, mut s2) = (0.0, 0.0);
        for &x in samples {
            let s0 = x + coeff * s1 - s2;
            s2 = s1;
            s1 = s0;
        }
        s1 * s1 + s2 * s2 - coeff * s1 * s2
    }

    /// The ID header, the comment header, and each channel's samples.
    type Decoded = (Vec<u8>, Vec<u8>, Vec<Vec<f64>>);

    /// Decode `ogg` with the pure-Rust decoder sipnab already ships, which
    /// shares no code with libopus: the file is read by an independent
    /// implementation, as a consumer of the container would read it.
    /// Returns the ID header, the comment header, and each channel's PCM
    /// after pre-skip, trimmed to the last page's granule position.
    fn decode(ogg: &[u8]) -> Result<Decoded, TestError> {
        let pages = pages(ogg)?;
        let mut packets = packets(&pages).into_iter();
        let head = packets.next().ok_or("an ID header")?;
        let tags = packets.next().ok_or("a comment header")?;
        let channels = usize::from(head[9]);
        let pre_skip = usize::from(u16::from_le_bytes(head[10..12].try_into()?));
        let mut decoder = crate::rtp::opus_decode::OpusStreamDecoder::new(48_000, channels)?;
        let mut pcm = Vec::new();
        for packet in packets {
            pcm.extend(decoder.decode_frame(&packet)?);
        }
        let last = pages.last().ok_or("pages")?.granule;
        let end = usize::try_from(last)? * channels;
        let kept = pcm
            .get(pre_skip * channels..end)
            .ok_or("granule past the decoded audio")?;
        let per_channel = (0..channels)
            .map(|c| {
                kept.iter()
                    .skip(c)
                    .step_by(channels)
                    .map(|&s| f64::from(s))
                    .collect()
            })
            .collect();
        Ok((head, tags, per_channel))
    }

    /// A two-channel 8 kHz call comes back from an independent decoder as
    /// the same two channels: the left tone on the left and the right tone
    /// on the right, as long as the input, at 48 kHz.
    #[test]
    fn a_two_way_call_round_trips_through_an_independent_decoder() -> Result<(), TestError> {
        let (left, right) = (tone(440.0, 8000, 2.0), tone(1000.0, 8000, 2.0));
        let ogg = encode(&stereo(&left, &right), 8000, 2, Some("the note"))?;
        let (head, _, channels) = decode(&ogg)?;
        assert_eq!(&head[..8], b"OpusHead");
        assert_eq!(head[9], 2, "two channels");
        assert_eq!(
            u32::from_le_bytes(head[12..16].try_into()?),
            8000,
            "input rate"
        );
        assert_eq!(channels.len(), 2);
        for (channel, (own, other)) in channels.iter().zip([(440.0, 1000.0), (1000.0, 440.0)]) {
            assert_eq!(channel.len(), 2 * 48_000, "two seconds at 48 kHz");
            let (p_own, p_other) = (
                power(channel, 48_000.0, own),
                power(channel, 48_000.0, other),
            );
            assert!(
                p_own > 100.0 * p_other,
                "{own} Hz dominates: {p_own} vs {p_other}"
            );
        }
        Ok(())
    }

    /// [RFC 7845 section 3](https://www.rfc-editor.org/rfc/rfc7845.html#section-3)'s layout: the ID header alone on the first page
    /// (beginning of stream), the comment header finishing the second, the
    /// audio after, the last page marked end of stream, granule positions
    /// zero on the header pages and rising after, one serial, and sequence
    /// numbers counting from zero.
    #[test]
    fn the_stream_has_the_layout_rfc_7845_requires() -> Result<(), TestError> {
        let ogg = encode(&tone(440.0, 8000, 3.0), 8000, 1, None)?;
        let pages = pages(&ogg)?;
        assert!(pages.len() >= 4, "{} pages", pages.len());
        assert_eq!(pages[0].header_type, 0x02, "BOS on the first page only");
        assert_eq!(pages[0].lacing.len(), 1, "the ID header alone");
        assert_eq!(&pages[0].body[..8], b"OpusHead");
        assert_eq!(&pages[1].body[..8], b"OpusTags");
        assert_ne!(pages[1].lacing.last(), Some(&255), "OpusTags ends its page");
        assert_eq!((pages[0].granule, pages[1].granule), (0, 0));
        let last = pages.len() - 1;
        for (i, page) in pages.iter().enumerate() {
            assert_eq!(page.sequence, u32::try_from(i)?);
            assert_eq!(page.serial, pages[0].serial);
            let eos = page.header_type & 0x04 != 0;
            assert_eq!(eos, i == last, "EOS on the last page only: page {i}");
            if i > 1 {
                assert!(
                    page.granule > pages[i - 1].granule,
                    "page {i} granule rises"
                );
            }
        }
        // Section 4: a page's granule counts every sample decoded through
        // its last packet, pre-skip included; 50 packets of 960 a page.
        for (n, page) in pages[2..last].iter().enumerate() {
            assert_eq!(
                page.granule,
                960 * 50 * (i64::try_from(n)? + 1),
                "audio page {n}"
            );
        }
        let pre_skip = i64::from(u16::from_le_bytes(pages[0].body[10..12].try_into()?));
        assert_eq!(
            pages[last].granule,
            pre_skip + 3 * 48_000,
            "end trimmed to the input"
        );
        Ok(())
    }

    /// Every audio packet is 20 ms at [`BITRATE_PER_CHANNEL`] per channel,
    /// constant: 60 bytes a channel.
    #[test]
    fn every_audio_packet_is_the_constant_bitrate() -> Result<(), TestError> {
        for channels in [1_u16, 2] {
            let mono = tone(300.0, 8000, 1.0);
            let input = if channels == 1 {
                mono.clone()
            } else {
                stereo(&mono, &mono)
            };
            let packets = packets(&pages(&encode(&input, 8000, channels, None)?)?);
            let expected = usize::try_from(BITRATE_PER_CHANNEL)? * usize::from(channels) / 8 / 50;
            let pre_skip = usize::from(u16::from_le_bytes(packets[0][10..12].try_into()?));
            // One second plus the lookahead (pre-skip at 48 kHz, /6 at 8 kHz),
            // in 160-sample frames.
            let frames = (8000 + pre_skip / 6).div_ceil(160);
            assert_eq!(
                packets.len(),
                2 + frames,
                "{channels}: two headers and the frames"
            );
            for packet in &packets[2..] {
                assert_eq!(packet.len(), expected, "{channels} channel(s)");
            }
        }
        Ok(())
    }

    /// The comment header names libopus as the vendor and carries the
    /// provenance note as `DESCRIPTION`.
    #[test]
    fn the_note_travels_as_the_description_comment() -> Result<(), TestError> {
        let note = "captured by sipnab at a tap; partial: the ring wrapped.";
        let ogg = encode(&tone(440.0, 8000, 0.1), 8000, 1, Some(note))?;
        let (_, tags, _) = decode(&ogg)?;
        assert_eq!(&tags[..8], b"OpusTags");
        let vendor_len = usize::try_from(u32::from_le_bytes(tags[8..12].try_into()?))?;
        let vendor = std::str::from_utf8(&tags[12..12 + vendor_len])?;
        assert!(vendor.starts_with("libopus"), "{vendor}");
        let mut at = 12 + vendor_len;
        let count = u32::from_le_bytes(tags[at..at + 4].try_into()?);
        assert_eq!(count, 1);
        at += 4;
        let len = usize::try_from(u32::from_le_bytes(tags[at..at + 4].try_into()?))?;
        let comment = std::str::from_utf8(&tags[at + 4..at + 4 + len])?;
        assert_eq!(comment, format!("DESCRIPTION={note}"));
        assert_eq!(at + 4 + len, tags.len(), "nothing after the comment");
        Ok(())
    }

    /// A rate libopus does not take is resampled to 48 kHz, and the ID
    /// header still names the input's own rate.
    #[test]
    fn an_input_rate_opus_does_not_take_is_resampled() -> Result<(), TestError> {
        let ogg = encode(&tone(440.0, 11_025, 1.0), 11_025, 1, None)?;
        let (head, _, channels) = decode(&ogg)?;
        assert_eq!(u32::from_le_bytes(head[12..16].try_into()?), 11_025);
        assert_eq!(channels[0].len(), 48_000, "one second at 48 kHz");
        let (p440, p1000) = (
            power(&channels[0], 48_000.0, 440.0),
            power(&channels[0], 48_000.0, 1000.0),
        );
        assert!(p440 > 100.0 * p1000, "{p440} vs {p1000}");
        Ok(())
    }

    /// A packet longer than one page holds (255 segments) continues on the
    /// next page, flagged as a continuation, and reassembles whole.
    #[test]
    fn a_long_comment_spans_pages_and_reassembles() -> Result<(), TestError> {
        let note = "n".repeat(70_000);
        let ogg = encode(&tone(440.0, 8000, 0.1), 8000, 1, Some(&note))?;
        let pages = pages(&ogg)?;
        assert!(
            pages.iter().any(|p| p.header_type & 0x01 != 0),
            "a continued page"
        );
        let tags = packets(&pages).into_iter().nth(1).ok_or("tags")?;
        assert!(tags.ends_with(note.as_bytes()));
        Ok(())
    }

    /// The Ogg CRC of RFC 3533: polynomial 0x04c11db7, initial value zero,
    /// not reflected. Checked against the value of "123456789" for that
    /// variant (CRC-32/MPEG-2 without the final inversion and initial ones).
    #[test]
    fn the_crc_is_the_ogg_crc() {
        assert_eq!(crc32(b"123456789"), 0x89A1_897F);
    }

    /// Anything other than one or two channels, and a zero rate, are refused.
    #[test]
    fn what_cannot_be_encoded_is_refused() {
        assert!(encode(&[0; 300], 8000, 3, None).is_err(), "three channels");
        assert!(encode(&[0; 300], 0, 1, None).is_err(), "zero rate");
    }
}
