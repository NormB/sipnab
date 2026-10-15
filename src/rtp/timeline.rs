// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where each retained frame belongs on its stream's RTP clock.
//!
//! The decoders turned the retained frames into audio one after another, so a
//! lost packet shortened the file by its own duration and everything after it
//! played early. RTP says where each frame belongs: its timestamp counts the
//! sampling instants of its first sample ([RFC 3550 section 5.1](https://www.rfc-editor.org/rfc/rfc3550.html#section-5.1)), so a frame
//! whose timestamp is ahead of where the previous frame ended has a gap in
//! front of it. That gap is filled with silence of the same length.
//!
//! Gaps are not all loss. A sender that stops sending during silence
//! ([RFC 3551 section 4.1](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.1), comfort noise) leaves the same hole in the
//! timestamps, and the timestamps alone cannot tell the two apart. Both are
//! time that passed with no audio received, which is what the fill
//! represents and what the export says.
//!
//! The fill is bounded by the stream's own wall-clock span. A timestamp jump
//! longer than the stream lasted is not time that passed: it is a sender that
//! reset its clock, or a hostile packet, and filling it would allocate silence
//! for as long as a 32-bit timestamp can reach. Such a jump is counted and not
//! filled.

/// What happens to one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Decode the frame, after `fill_ticks` ticks of the RTP clock of silence.
    Play {
        /// Ticks of silence in front of the frame.
        fill_ticks: u64,
    },
    /// The frame repeats or falls inside audio already placed: skip it.
    Drop,
}

/// What a timeline did, for the export's summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimelineReport {
    /// Gaps filled with silence.
    pub gaps: u64,
    /// Their total length, in ticks of the RTP clock.
    pub filled_ticks: u64,
    /// Frames whose timestamp repeated one already placed.
    pub duplicates: u64,
    /// Frames that arrived after audio past them had been placed (live
    /// route only; the export sorts first).
    pub late: u64,
    /// Timestamp jumps too long to be time that passed, left unfilled.
    pub jumps: u64,
}

impl TimelineReport {
    /// The filled time in milliseconds on a `clock_rate` RTP clock.
    #[must_use]
    pub fn filled_ms(&self, clock_rate: u32) -> u64 {
        ticks_to_samples(self.filled_ticks, clock_rate, 1000)
    }
}

/// One stream's position on its RTP clock.
#[derive(Debug, Clone)]
pub struct Timeline {
    /// The RTP clock, in Hz. Zero when the stream's clock is unknown.
    clock_rate: u32,
    /// Whether gaps are filled, or closed up.
    fill: bool,
    /// The most the fills may add up to, in ticks: the stream's wall-clock
    /// span on its own clock.
    budget_ticks: u64,
    /// The previous frame in arrival order, raw and unwrapped, so the next
    /// one can be unwrapped against it.
    last_raw: Option<u32>,
    /// That frame's unwrapped timestamp.
    last_ext: i64,
    /// The unwrapped timestamp of the last frame placed.
    placed_ext: Option<i64>,
    /// Where the audio placed so far ends, unwrapped.
    end_ext: i64,
    /// What it has done so far.
    report: TimelineReport,
}

impl Timeline {
    /// A timeline for a stream on a `clock_rate` RTP clock that lasted
    /// `wall_ms` milliseconds of capture time. `fill` false places frames in
    /// order and drops repeats, but leaves gaps closed.
    #[must_use]
    pub fn new(clock_rate: u32, wall_ms: u64, fill: bool) -> Self {
        Self {
            clock_rate,
            fill,
            budget_ticks: ticks_from_ms(wall_ms, clock_rate),
            last_raw: None,
            last_ext: 0,
            placed_ext: None,
            end_ext: 0,
            report: TimelineReport::default(),
        }
    }

    /// Raise the fill budget to a stream that has now lasted `wall_ms`.
    pub fn extend_wall(&mut self, wall_ms: u64) {
        self.budget_ticks = self
            .budget_ticks
            .max(ticks_from_ms(wall_ms, self.clock_rate));
    }

    /// The step for the next frame, stamped `ts`.
    pub fn step(&mut self, ts: u32) -> Step {
        let ext = match self.last_raw {
            // The signed difference is the unwrap: a step across 2^32 is a
            // small positive number, and a reordered frame a small negative.
            Some(raw) => self.last_ext + i64::from(ts.wrapping_sub(raw) as i32),
            None => 0,
        };
        self.last_raw = Some(ts);
        self.last_ext = ext;
        let Some(placed) = self.placed_ext else {
            self.place(ext);
            return Step::Play { fill_ticks: 0 };
        };
        if ext == placed {
            self.report.duplicates = self.report.duplicates.saturating_add(1);
            return Step::Drop;
        }
        if ext < self.end_ext {
            self.report.late = self.report.late.saturating_add(1);
            return Step::Drop;
        }
        let gap = u64::try_from(ext - self.end_ext).unwrap_or(0);
        self.place(ext);
        if gap == 0 || !self.fill || self.clock_rate == 0 {
            return Step::Play { fill_ticks: 0 };
        }
        let total = self.report.filled_ticks.saturating_add(gap);
        if total > self.budget_ticks {
            self.report.jumps = self.report.jumps.saturating_add(1);
            return Step::Play { fill_ticks: 0 };
        }
        self.report.gaps = self.report.gaps.saturating_add(1);
        self.report.filled_ticks = total;
        Step::Play { fill_ticks: gap }
    }

    /// The frame just played lasted `ticks` ticks of the RTP clock.
    pub fn played(&mut self, ticks: u64) {
        let ticks = i64::try_from(ticks).unwrap_or(i64::MAX);
        self.end_ext = self.placed_ext.unwrap_or(0).saturating_add(ticks);
    }

    /// Put the next frame at `ext`. Its audio ends there until
    /// [`played`](Self::played) says how long it lasted, so a frame that
    /// failed to decode leaves its own time to the next frame's gap.
    fn place(&mut self, ext: i64) {
        self.placed_ext = Some(ext);
        self.end_ext = ext;
    }

    /// What this timeline has done so far.
    #[must_use]
    pub fn report(&self) -> TimelineReport {
        self.report
    }
}

/// Indices of `stamps` in RTP timestamp order, earliest first.
///
/// Arrival order is not timestamp order once the network reorders, and the
/// timestamps wrap at 2^32, so each is unwrapped against the one before it in
/// arrival order before sorting. Stable, so repeats keep their arrival order.
#[must_use]
pub fn timestamp_order(stamps: &[u32]) -> Vec<usize> {
    let mut ext: Vec<(i64, usize)> = Vec::with_capacity(stamps.len());
    let mut last: Option<(u32, i64)> = None;
    for (i, &ts) in stamps.iter().enumerate() {
        let e = match last {
            Some((raw, e)) => e + i64::from(ts.wrapping_sub(raw) as i32),
            None => 0,
        };
        last = Some((ts, e));
        ext.push((e, i));
    }
    ext.sort_by_key(|&(e, _)| e);
    ext.into_iter().map(|(_, i)| i).collect()
}

/// `ticks` of a `clock_rate` RTP clock as samples at `rate`.
#[must_use]
pub fn ticks_to_samples(ticks: u64, clock_rate: u32, rate: u32) -> u64 {
    if clock_rate == 0 {
        return 0;
    }
    let samples = u128::from(ticks) * u128::from(rate) / u128::from(clock_rate);
    u64::try_from(samples).unwrap_or(u64::MAX)
}

/// `samples` at `rate` as ticks of a `clock_rate` RTP clock.
#[must_use]
pub fn samples_to_ticks(samples: u64, rate: u32, clock_rate: u32) -> u64 {
    if rate == 0 {
        return 0;
    }
    ticks_to_samples(samples, rate, clock_rate)
}

/// `ms` milliseconds as ticks of a `clock_rate` RTP clock.
fn ticks_from_ms(ms: u64, clock_rate: u32) -> u64 {
    ticks_to_samples(ms, 1000, clock_rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 20 ms G.711 frame on the 8 kHz clock.
    const FRAME: u64 = 160;

    /// Play `stamps` through a timeline, each frame lasting `FRAME` ticks, and
    /// return the steps.
    fn run(t: &mut Timeline, stamps: &[u32]) -> Vec<Step> {
        stamps
            .iter()
            .map(|&ts| {
                let step = t.step(ts);
                if matches!(step, Step::Play { .. }) {
                    t.played(FRAME);
                }
                step
            })
            .collect()
    }

    const PLAY: Step = Step::Play { fill_ticks: 0 };

    /// Back-to-back frames have no gap between them.
    #[test]
    fn contiguous_frames_need_no_fill() {
        let mut t = Timeline::new(8000, 1_000, true);
        assert_eq!(run(&mut t, &[0, 160, 320]), vec![PLAY, PLAY, PLAY]);
        assert_eq!(t.report(), TimelineReport::default());
    }

    /// One lost 20 ms packet is one gap of its own length.
    #[test]
    fn a_lost_packet_is_a_gap_of_its_length() {
        let mut t = Timeline::new(8000, 1_000, true);
        let steps = run(&mut t, &[0, 160, 480]);
        assert_eq!(steps[2], Step::Play { fill_ticks: 160 });
        let r = t.report();
        assert_eq!((r.gaps, r.filled_ticks), (1, 160));
        assert_eq!(r.filled_ms(8000), 20);
    }

    /// A repeated timestamp is a duplicate packet, not more audio.
    #[test]
    fn a_repeated_timestamp_is_dropped() {
        let mut t = Timeline::new(8000, 1_000, true);
        assert_eq!(
            run(&mut t, &[0, 160, 160, 320]),
            vec![PLAY, PLAY, Step::Drop, PLAY]
        );
        assert_eq!(t.report().duplicates, 1);
    }

    /// A frame that falls inside audio already placed arrived too late for a
    /// reader that cannot go back.
    #[test]
    fn a_frame_behind_the_timeline_is_late() {
        let mut t = Timeline::new(8000, 1_000, true);
        assert_eq!(
            run(&mut t, &[0, 320, 160]),
            vec![PLAY, Step::Play { fill_ticks: 160 }, Step::Drop]
        );
        assert_eq!(t.report().late, 1);
    }

    /// The timestamp wraps at 2^32 and the timeline does not notice.
    #[test]
    fn the_wrap_is_contiguous() {
        let mut t = Timeline::new(8000, 1_000, true);
        let start = u32::MAX - 159;
        assert_eq!(
            run(&mut t, &[start, 0, 320]),
            vec![PLAY, PLAY, Step::Play { fill_ticks: 160 }]
        );
    }

    /// A jump longer than the stream lasted is not time that passed. Filling
    /// it would allocate a quarter of 2^32 samples on one hostile packet.
    #[test]
    fn a_jump_longer_than_the_stream_is_not_filled() {
        let mut t = Timeline::new(8000, 40, true);
        assert_eq!(
            run(&mut t, &[0, 0x4000_0000, 0x4000_00A0]),
            vec![PLAY, PLAY, PLAY]
        );
        let r = t.report();
        assert_eq!((r.jumps, r.gaps, r.filled_ticks), (1, 0, 0));
    }

    /// The budget is the whole stream's: gaps that each fit but together
    /// exceed the wall-clock span stop being filled once it is spent.
    #[test]
    fn the_fill_budget_is_cumulative() {
        // 60 ms of wall clock is 480 ticks; three 200-tick gaps exceed it.
        let mut t = Timeline::new(8000, 60, true);
        let steps = run(&mut t, &[0, 360, 720, 1080]);
        assert_eq!(steps[1], Step::Play { fill_ticks: 200 });
        assert_eq!(steps[2], Step::Play { fill_ticks: 200 });
        assert_eq!(steps[3], PLAY);
        let r = t.report();
        assert_eq!((r.gaps, r.filled_ticks, r.jumps), (2, 400, 1));
    }

    /// A live reader's budget grows as the call goes on.
    #[test]
    fn extending_the_wall_clock_raises_the_budget() {
        let mut t = Timeline::new(8000, 0, true);
        assert_eq!(run(&mut t, &[0]), vec![PLAY]);
        t.extend_wall(1_000);
        assert_eq!(run(&mut t, &[480]), vec![Step::Play { fill_ticks: 320 }]);
    }

    /// Without fill, frames are still ordered and deduplicated, and gaps
    /// close up: the measurement that reads what the sender's samples DID.
    #[test]
    fn without_fill_gaps_close_and_are_not_counted() {
        let mut t = Timeline::new(8000, 1_000, false);
        assert_eq!(run(&mut t, &[0, 480, 480]), vec![PLAY, PLAY, Step::Drop]);
        let r = t.report();
        assert_eq!((r.gaps, r.filled_ticks, r.duplicates), (0, 0, 1));
    }

    /// An unknown clock rate leaves nothing to measure a gap in.
    #[test]
    fn an_unknown_clock_fills_nothing() {
        let mut t = Timeline::new(0, 1_000, true);
        assert_eq!(run(&mut t, &[0, 480]), vec![PLAY, PLAY]);
        assert_eq!(t.report().gaps, 0);
    }

    /// Reordered arrivals sort into timestamp order, across the wrap, and
    /// repeats keep their arrival order.
    #[test]
    fn timestamp_order_sorts_across_the_wrap() {
        let near = u32::MAX - 159;
        assert_eq!(timestamp_order(&[near, 160, 0, 160]), vec![0, 2, 1, 3]);
        assert_eq!(timestamp_order(&[0, 320, 160]), vec![0, 2, 1]);
        assert!(timestamp_order(&[]).is_empty());
    }

    /// G.722's RTP clock runs at 8 kHz under 16 kHz samples (RFC 3551
    /// section 4.5.2), so a tick is two samples.
    #[test]
    fn ticks_and_samples_convert_at_the_decoder_rate() {
        assert_eq!(ticks_to_samples(160, 8000, 16000), 320);
        assert_eq!(samples_to_ticks(320, 16000, 8000), 160);
        assert_eq!(ticks_to_samples(160, 8000, 8000), 160);
        assert_eq!(ticks_to_samples(960, 48000, 48000), 960);
        assert_eq!(ticks_to_samples(160, 0, 8000), 0);
        assert_eq!(samples_to_ticks(160, 0, 8000), 0);
    }
}
