//! Aggregation core for the live call-quality dashboard.
//!
//! Pure data layer: ranks every tracked RTP stream by current MOS and
//! precomputes the per-stream trend series the dashboard view draws.
//! No locking and no rendering here — the renderer receives an
//! already-built [`DashboardSnapshot`] so the draw pass stays read-only
//! (skip-tick contract).

use crate::rtp::quality::estimate_mos;
use crate::rtp::stream::{RtpStream, StreamKey};
use crate::rtp::stream_store::StreamStore;

/// One point of a per-stream quality trend (one 5 s quality interval).
#[derive(Debug, Clone, PartialEq)]
pub struct TrendPoint {
    /// Estimated MOS for the interval.
    pub mos: f64,
    /// Average jitter during the interval (milliseconds).
    pub jitter_ms: f64,
    /// Packet loss percentage during the interval.
    pub loss_pct: f64,
}

/// Current health of a single RTP stream, ready for table display.
#[derive(Debug, Clone)]
pub struct StreamHealth {
    /// Identity of the stream.
    pub key: StreamKey,
    /// SIP Call-ID when the stream is linked to a dialog.
    pub call_id: Option<String>,
    /// Codec name, if known.
    pub codec: Option<String>,
    /// Current estimated MOS from running jitter/loss.
    pub mos: f64,
    /// Running RFC 3550 jitter (milliseconds).
    pub jitter_ms: f64,
    /// Cumulative packet loss percentage.
    pub loss_pct: f64,
    /// Total packets received.
    pub packets: u64,
    /// `true` if the stream saw traffic in the last 30 s.
    pub active: bool,
    /// Per-interval trend, oldest first.
    pub trend: Vec<TrendPoint>,
}

/// Aggregate view over every stream in the store, worst quality first.
#[derive(Debug, Clone, Default)]
pub struct DashboardSnapshot {
    /// Total streams tracked.
    pub total_streams: usize,
    /// Streams active within the last 30 s.
    pub active_streams: usize,
    /// Mean MOS across all streams (`None` when empty).
    pub avg_mos: Option<f64>,
    /// Lowest MOS across all streams (`None` when empty).
    pub worst_mos: Option<f64>,
    /// Streams with any recorded packet loss.
    pub streams_with_loss: usize,
    /// Per-stream health rows, ascending MOS (worst first); ties broken
    /// by higher loss first, then by stream key for determinism.
    pub rows: Vec<StreamHealth>,
}

/// Cumulative loss percentage of a stream; `0.0` for an empty stream.
fn stream_loss_pct(s: &RtpStream) -> f64 {
    let total = s.packet_count + s.lost_packets;
    if total > 0 {
        (s.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    }
}

impl DashboardSnapshot {
    /// Build a snapshot from the stream store.
    ///
    /// Runs under the store read guard on the render path — O(streams)
    /// with no allocation beyond the output itself.
    pub fn from_streams(store: &StreamStore) -> Self {
        let mut rows: Vec<StreamHealth> = store
            .iter()
            .map(|s| {
                let loss_pct = stream_loss_pct(s);
                let codec = s.codec.clone();
                let mos = estimate_mos(s.jitter, loss_pct, codec.as_deref());
                let trend = s
                    .quality_intervals
                    .iter()
                    .map(|qi| TrendPoint {
                        mos: estimate_mos(qi.jitter_ms, qi.loss_pct, codec.as_deref()),
                        jitter_ms: qi.jitter_ms,
                        loss_pct: qi.loss_pct,
                    })
                    .collect();
                StreamHealth {
                    key: s.key.clone(),
                    call_id: s.associated_dialog.clone(),
                    codec,
                    mos,
                    jitter_ms: s.jitter,
                    loss_pct,
                    packets: s.packet_count,
                    active: s.is_active(),
                    trend,
                }
            })
            .collect();

        rows.sort_by(|a, b| {
            a.mos
                .total_cmp(&b.mos)
                .then(b.loss_pct.total_cmp(&a.loss_pct))
                .then_with(|| {
                    (a.key.ssrc, a.key.src, a.key.dst).cmp(&(b.key.ssrc, b.key.src, b.key.dst))
                })
        });

        let total_streams = rows.len();
        let active_streams = rows.iter().filter(|r| r.active).count();
        let streams_with_loss = rows.iter().filter(|r| r.loss_pct > 0.0).count();
        let avg_mos = (total_streams > 0)
            .then(|| rows.iter().map(|r| r.mos).sum::<f64>() / total_streams as f64);
        let worst_mos = rows.first().map(|r| r.mos);

        Self {
            total_streams,
            active_streams,
            avg_mos,
            worst_mos,
            streams_with_loss,
            rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::parser::RtpHeader;
    use chrono::{Duration, Utc};
    use std::net::SocketAddr;

    fn header(seq: u16, ts: u32) -> RtpHeader {
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0, // PCMU
            sequence: seq,
            timestamp: ts,
            ssrc: 0xABCD,
            payload_offset: 12,
        }
    }

    fn addr(port: u16) -> SocketAddr {
        format!("192.0.2.10:{port}").parse().unwrap()
    }

    /// A stream with `n` clean packets ending "now" (active).
    fn clean_stream(ssrc: u32, n: u16) -> RtpStream {
        let start = Utc::now();
        let key = StreamKey {
            ssrc,
            src: addr(10000),
            dst: addr(20000),
        };
        let mut s = RtpStream::new(key, &header(0, 0), start);
        for i in 1..n {
            s.update(
                &header(i, u32::from(i) * 160),
                start + Duration::milliseconds(i64::from(i) * 20),
                160,
            );
        }
        s
    }

    fn store_with(streams: Vec<RtpStream>) -> StreamStore {
        let mut store = StreamStore::new(64);
        for s in streams {
            store.insert_for_test(s);
        }
        store
    }

    #[test]
    fn empty_store_yields_empty_snapshot() {
        let snap = DashboardSnapshot::from_streams(&StreamStore::new(64));
        assert_eq!(snap.total_streams, 0);
        assert_eq!(snap.active_streams, 0);
        assert_eq!(snap.avg_mos, None);
        assert_eq!(snap.worst_mos, None);
        assert_eq!(snap.streams_with_loss, 0);
        assert!(snap.rows.is_empty());
    }

    #[test]
    fn single_clean_stream_scores_high_and_matches_aggregates() {
        let snap = DashboardSnapshot::from_streams(&store_with(vec![clean_stream(1, 50)]));
        assert_eq!(snap.total_streams, 1);
        assert_eq!(snap.active_streams, 1);
        assert_eq!(snap.streams_with_loss, 0);
        assert_eq!(snap.rows.len(), 1);
        let row = &snap.rows[0];
        assert!(
            row.mos > 4.0,
            "clean PCMU stream must score >4.0, got {}",
            row.mos
        );
        assert_eq!(row.loss_pct, 0.0);
        assert_eq!(snap.avg_mos, Some(row.mos));
        assert_eq!(snap.worst_mos, Some(row.mos));
        assert!(row.active);
        assert_eq!(row.call_id, None);
    }

    #[test]
    fn lossy_stream_ranks_first_and_is_counted() {
        let clean = clean_stream(1, 50);
        let mut lossy = clean_stream(2, 50);
        lossy.lost_packets = 25; // ~33% loss
        let snap = DashboardSnapshot::from_streams(&store_with(vec![clean, lossy]));
        assert_eq!(snap.total_streams, 2);
        assert_eq!(snap.streams_with_loss, 1);
        assert_eq!(snap.rows.len(), 2);
        assert_eq!(
            snap.rows[0].key.ssrc, 2,
            "worst (lossy) stream must rank first"
        );
        assert!(snap.rows[0].mos < snap.rows[1].mos);
        assert!(snap.rows[0].loss_pct > 30.0 && snap.rows[0].loss_pct < 35.0);
        assert_eq!(snap.worst_mos, Some(snap.rows[0].mos));
        let avg = (snap.rows[0].mos + snap.rows[1].mos) / 2.0;
        assert!((snap.avg_mos.unwrap() - avg).abs() < 1e-9);
    }

    #[test]
    fn all_lost_stream_reports_full_loss_without_panicking() {
        // adversarial: every packet after the first was lost
        let mut s = clean_stream(3, 1);
        s.packet_count = 0; // hypothetical: nothing received
        s.lost_packets = 100;
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        assert_eq!(snap.rows[0].loss_pct, 100.0);
        assert!(snap.rows[0].mos >= 1.0, "MOS stays clamped at >=1.0");
    }

    #[test]
    fn zero_packet_stream_is_handled() {
        // adversarial: a stream object with no traffic at all
        let mut s = clean_stream(4, 1);
        s.packet_count = 0;
        s.lost_packets = 0;
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        assert_eq!(snap.total_streams, 1);
        assert_eq!(snap.rows[0].loss_pct, 0.0);
    }

    #[test]
    fn associated_dialog_and_orphan_flow_through() {
        let mut linked = clean_stream(5, 10);
        linked.associated_dialog = Some("call-1@example.com".into());
        let mut orphan = clean_stream(6, 10);
        orphan.orphaned = true;
        let snap = DashboardSnapshot::from_streams(&store_with(vec![linked, orphan]));
        let linked_row = snap.rows.iter().find(|r| r.key.ssrc == 5).unwrap();
        let orphan_row = snap.rows.iter().find(|r| r.key.ssrc == 6).unwrap();
        assert_eq!(linked_row.call_id.as_deref(), Some("call-1@example.com"));
        assert_eq!(orphan_row.call_id, None);
    }

    #[test]
    fn inactive_stream_is_counted_but_not_active() {
        let mut old = clean_stream(7, 10);
        old.last_seen = Utc::now() - Duration::seconds(120);
        let snap = DashboardSnapshot::from_streams(&store_with(vec![old]));
        assert_eq!(snap.total_streams, 1);
        assert_eq!(snap.active_streams, 0);
        assert!(!snap.rows[0].active);
    }

    #[test]
    fn trend_is_built_from_quality_intervals_oldest_first() {
        let start = Utc::now();
        let mut s = clean_stream(8, 2);
        // two intervals: first clean, second degraded
        s.quality_intervals.clear();
        s.quality_intervals
            .push(crate::rtp::stream::QualityInterval {
                timestamp: start,
                jitter_ms: 1.0,
                loss_pct: 0.0,
                packets: 250,
            });
        s.quality_intervals
            .push(crate::rtp::stream::QualityInterval {
                timestamp: start + Duration::seconds(5),
                jitter_ms: 80.0,
                loss_pct: 20.0,
                packets: 200,
            });
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        let trend = &snap.rows[0].trend;
        assert_eq!(trend.len(), 2);
        assert!(
            trend[0].mos > trend[1].mos,
            "clean interval first, degraded second"
        );
        assert_eq!(trend[0].loss_pct, 0.0);
        assert_eq!(trend[1].jitter_ms, 80.0);
        assert_eq!(trend[1].loss_pct, 20.0);
        // trend MOS must agree with the canonical estimator
        let expect = estimate_mos(80.0, 20.0, snap.rows[0].codec.as_deref());
        assert!((trend[1].mos - expect).abs() < 1e-9);
    }
}
