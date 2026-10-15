// SPDX-License-Identifier: MIT OR Apache-2.0

//! A stream's retained audio, decoded as it arrives: what the live audio
//! route sends while a call is in progress.
//!
//! The retained payloads are a queue that can lose its START (a ring cap, the
//! retention budget, a release after a live vCon was written), so a reader
//! cannot keep an index into it. It keeps a count of every frame the stream
//! has ever retained instead: the first frame still held is that count less
//! what is held, and what the reader has not yet decoded is everything past
//! its own count.

use crate::rtp::audio_export::{FrameDecoder, stream_wall_ms};
use crate::rtp::stream::RtpStream;
use crate::rtp::timeline::{Step, Timeline, samples_to_ticks, ticks_to_samples};

/// `call_id`'s streams in the order live audio numbers them: first seen
/// first, SSRC breaking a tie.
#[must_use]
pub fn call_streams<'a>(
    ss: &'a crate::rtp::stream_store::StreamStore,
    call_id: &'a str,
) -> Vec<&'a RtpStream> {
    let mut streams: Vec<&RtpStream> = ss.streams_for(call_id).collect();
    streams.sort_by(|a, b| {
        a.first_seen
            .cmp(&b.first_seen)
            .then(a.key.ssrc.cmp(&b.key.ssrc))
    });
    streams
}

/// One stream being followed.
pub struct LiveStream {
    /// The decoder, carrying the codec's state from frame to frame.
    decoder: FrameDecoder,
    /// How many of the stream's frames, counted from the first it ever
    /// retained, this reader has taken.
    taken: u64,
    /// Frames that were released before this reader took them.
    missed: u64,
    /// Where the frames fall on the stream's RTP clock, so a lost packet is
    /// sent as silence of its length (see [`crate::rtp::timeline`]).
    timeline: Timeline,
}

/// What one look at a stream found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Frames {
    /// Each new frame, decoded, in order.
    pub pcm: Vec<Vec<i16>>,
    /// Frames released from the stream's start before they were read since
    /// the last look; the audio has a gap of this many frames before `pcm`.
    pub missed: u64,
    /// Frames the decoder refused.
    pub failed: u64,
}

/// How many frames `stream` has retained since it began: those released from
/// its start plus those it holds.
fn retained_ever(stream: &RtpStream) -> u64 {
    released(stream).saturating_add(stream.payload_buffer.len() as u64)
}

/// How many frames have left the start of `stream`'s buffer.
fn released(stream: &RtpStream) -> u64 {
    stream
        .payload_frames_dropped
        .saturating_add(stream.payload_frames_released)
        .saturating_add(stream.payload_frames_released_after_export)
}

impl LiveStream {
    /// Follow `stream` from its first retained frame.
    ///
    /// # Errors
    ///
    /// The stream's codec has no decoder.
    pub fn new(stream: &RtpStream) -> anyhow::Result<Self> {
        Ok(Self {
            decoder: FrameDecoder::new(stream.codec.as_deref())?,
            taken: 0,
            missed: 0,
            timeline: Timeline::new(stream.clock_rate, stream_wall_ms(stream), true),
        })
    }

    /// The rate of the samples this stream decodes to.
    #[must_use]
    pub fn rate(&self, stream: &RtpStream) -> u32 {
        self.decoder.rate(stream.clock_rate)
    }

    /// Frames released before this reader took them, over its whole life.
    #[must_use]
    pub fn missed(&self) -> u64 {
        self.missed
    }

    /// Decode every frame `stream` has retained since the last call.
    pub fn next(&mut self, stream: &RtpStream) -> Frames {
        let first_held = released(stream);
        let mut frames = Frames::default();
        if self.taken < first_held {
            frames.missed = first_held - self.taken;
            self.missed = self.missed.saturating_add(frames.missed);
            self.taken = first_held;
        }
        let skip = usize::try_from(self.taken - first_held).unwrap_or(usize::MAX);
        let clock = stream.clock_rate;
        let rate = self.decoder.rate(clock);
        self.timeline.extend_wall(stream_wall_ms(stream));
        for (ts, payload) in stream.payload_buffer.iter().skip(skip) {
            let Step::Play { fill_ticks } = self.timeline.step(*ts) else {
                continue;
            };
            // Bounded by the timeline's budget, the stream's own wall-clock
            // span, so a hostile timestamp cannot size this allocation.
            let silence = usize::try_from(ticks_to_samples(fill_ticks, clock, rate)).unwrap_or(0);
            if silence > 0 {
                frames.pcm.push(vec![0; silence]);
            }
            match self.decoder.decode(payload) {
                Ok(pcm) => {
                    self.timeline
                        .played(samples_to_ticks(pcm.len() as u64, rate, clock));
                    frames.pcm.push(pcm);
                }
                Err(_) => frames.failed = frames.failed.saturating_add(1),
            }
        }
        self.taken = retained_ever(stream).max(self.taken);
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A stream carrying `codec` with no frames yet.
    fn stream(codec: &str) -> Result<RtpStream, TestError> {
        let key = crate::rtp::stream::StreamKey {
            ssrc: 1,
            src: "10.0.0.1:20000".parse()?,
            dst: "10.0.0.2:30000".parse()?,
            session: 0,
        };
        let hdr = crate::rtp::parser::RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 9,
            sequence: 1,
            timestamp: 0,
            ssrc: 1,
            payload_offset: 12,
        };
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).ok_or("a time")?;
        let mut s = RtpStream::new(key, &hdr, ts);
        s.codec = Some(codec.to_owned());
        s.clock_rate = 8000;
        Ok(s)
    }

    /// G.722 frames from the fixture, 160 bytes each.
    fn g722_frames() -> Result<Vec<Vec<u8>>, TestError> {
        Ok(std::fs::read("tests/fixtures/g722/tone440.g722")?
            .chunks(160)
            .map(<[u8]>::to_vec)
            .collect())
    }

    /// Read a few frames at a time, the decode equals the whole stream's, and
    /// each look returns only what arrived since the last.
    #[test]
    fn reading_as_frames_arrive_equals_reading_at_once() -> Result<(), TestError> {
        let frames = g722_frames()?;
        let whole = crate::rtp::g722::Decoder::default().decode(&frames.concat());
        let mut s = stream("G722")?;
        let mut live = LiveStream::new(&s)?;
        assert_eq!(live.rate(&s), 16000);
        let mut got: Vec<i16> = Vec::new();
        let mut ts = 0u32;
        for (i, chunk) in frames.chunks(7).enumerate() {
            for f in chunk {
                s.payload_buffer.push_back((ts, f.clone()));
                ts = ts.wrapping_add(160);
            }
            let found = live.next(&s);
            assert_eq!(
                found.pcm.len(),
                chunk.len(),
                "look {i} returns only the new frames"
            );
            assert_eq!(found.missed, 0);
            got.extend(found.pcm.concat());
        }
        assert_eq!(got, whole);
        assert!(
            live.next(&s).pcm.is_empty(),
            "nothing new, nothing returned"
        );
        Ok(())
    }

    /// Frames released from the start before they were read are a gap, said
    /// so, and the reader carries on from the first frame still held.
    #[test]
    fn frames_released_before_reading_are_a_counted_gap() -> Result<(), TestError> {
        let mut s = stream("PCMU")?;
        let mut live = LiveStream::new(&s)?;
        for n in 0..10u8 {
            s.payload_buffer
                .push_back((u32::from(n) * 160, vec![n; 160]));
        }
        assert_eq!(live.next(&s).pcm.len(), 10);
        for n in 10..20u8 {
            s.payload_buffer
                .push_back((u32::from(n) * 160, vec![n; 160]));
        }
        // The first 15 leave the buffer: 10 already read, 5 not.
        s.payload_buffer.drain(..15);
        s.payload_frames_released = 15;
        let found = live.next(&s);
        assert_eq!(found.missed, 5);
        assert_eq!(found.pcm.len(), 5);
        assert_eq!(
            found.pcm[0],
            crate::rtp::g711::decode_frame(crate::rtp::g711::G711Codec::Ulaw, &[15; 160])
        );
        assert_eq!(live.missed(), 5);
        // Released after reading: no gap.
        s.payload_buffer.drain(..2);
        s.payload_frames_released_after_export = 2;
        s.payload_buffer.push_back((20 * 160, vec![20; 160]));
        let found = live.next(&s);
        assert_eq!((found.missed, found.pcm.len()), (0, 1));
        Ok(())
    }

    /// A packet lost between two looks is silence of its length, sent in
    /// its place, so a listener's audio stays on the call's clock.
    #[test]
    fn a_lost_packet_between_looks_is_sent_as_silence() -> Result<(), TestError> {
        let mut s = stream("PCMU")?;
        let mut live = LiveStream::new(&s)?;
        s.payload_buffer.push_back((0, vec![0x00; 160]));
        assert_eq!(live.next(&s).pcm.len(), 1);
        s.payload_buffer.push_back((480, vec![0x00; 160]));
        s.last_seen = s.first_seen + chrono::Duration::milliseconds(60);
        let found = live.next(&s);
        assert_eq!(found.pcm.len(), 2, "the silence, then the frame");
        assert_eq!(found.pcm[0], vec![0i16; 320]);
        assert_eq!(found.pcm[1].len(), 160);
        Ok(())
    }

    /// A packet repeated across two looks plays once.
    #[test]
    fn a_repeated_packet_plays_once() -> Result<(), TestError> {
        let mut s = stream("PCMU")?;
        let mut live = LiveStream::new(&s)?;
        s.payload_buffer.push_back((0, vec![0x00; 160]));
        assert_eq!(live.next(&s).pcm.len(), 1);
        s.payload_buffer.push_back((0, vec![0x00; 160]));
        s.payload_buffer.push_back((160, vec![0x00; 160]));
        assert_eq!(live.next(&s).pcm.len(), 1);
        Ok(())
    }

    /// A codec with no decoder is refused when the stream is followed.
    #[test]
    fn a_codec_with_no_decoder_is_refused() -> Result<(), TestError> {
        assert!(LiveStream::new(&stream("G729")?).is_err());
        Ok(())
    }
}
