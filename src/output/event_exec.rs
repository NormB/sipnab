//! Event exec hooks for triggering external commands.
//!
//! Fires shell commands when dialog state changes or RTP quality degrades
//! below a threshold. Supports template expansion, rate limiting, and
//! non-blocking execution with queue depth caps.

use std::process::Command;
use std::time::Instant;

use log::warn;

use crate::rtp::stream::RtpStream;
use crate::sip::dialog::SipDialog;

/// Maximum number of pending child processes before dropping events.
const MAX_QUEUE_DEPTH: usize = 100;

/// Engine for executing external commands on SIP/RTP events.
///
/// Supports two event types:
/// - Dialog events: fired when a dialog changes state.
/// - Quality events: fired when an RTP stream's estimated MOS drops below
///   a threshold.
///
/// Commands use template variables (`%call_id`, `%json`, etc.) that are
/// expanded before execution. Rate limiting prevents runaway execution.
pub struct EventExecEngine {
    /// Command template for dialog events. `None` disables dialog hooks.
    on_dialog_cmd: Option<String>,
    /// Command template for quality events. `None` disables quality hooks.
    on_quality_cmd: Option<String>,
    /// Maximum command executions per second.
    rate_limit: u32,
    /// MOS threshold below which quality events fire.
    quality_threshold: f64,
    /// Timestamp of the start of the current rate-limit window.
    window_start: Instant,
    /// Number of execs in the current one-second window.
    exec_count_this_second: u32,
    /// Current number of spawned (pending) child processes.
    queue_depth: usize,
}

impl EventExecEngine {
    /// Create a new event exec engine.
    ///
    /// # Arguments
    ///
    /// * `on_dialog_cmd` — Command template for dialog events (e.g.,
    ///   `"curl -X POST http://hook/dialog --data '%json'"`)
    /// * `on_quality_cmd` — Command template for quality events
    /// * `rate_limit` — Maximum executions per second (0 = unlimited)
    /// * `quality_threshold` — MOS score below which quality events fire
    pub fn new(
        on_dialog_cmd: Option<String>,
        on_quality_cmd: Option<String>,
        rate_limit: u32,
        quality_threshold: f64,
    ) -> Self {
        Self {
            on_dialog_cmd,
            on_quality_cmd,
            rate_limit,
            quality_threshold,
            window_start: Instant::now(),
            exec_count_this_second: 0,
            queue_depth: 0,
        }
    }

    /// Fire a dialog event, expanding templates and spawning the command.
    ///
    /// Template variables:
    /// - `%json` — Full dialog JSON (via [`super::json::dialog_to_json`])
    /// - `%call_id` — The dialog's Call-ID
    /// - `%from` — From user
    /// - `%to` — To user
    /// - `%state` — Dialog state (e.g., "Completed")
    /// - `%method` — Initial method (e.g., "INVITE")
    pub fn fire_dialog_event(&mut self, dialog: &SipDialog) {
        let template = match &self.on_dialog_cmd {
            Some(cmd) => cmd.clone(),
            None => return,
        };

        if !self.check_rate_limit() {
            return;
        }

        // Build the JSON for %json template
        let json = super::json::dialog_to_json(
            dialog,
            &[],
            &crate::rtp::diagnosis::MediaDiagnosis::default(),
        );

        let cmd = template
            .replace("%json", &shell_escape(&json))
            .replace("%call_id", &shell_escape(&dialog.call_id))
            .replace(
                "%from",
                &shell_escape(dialog.from_user.as_deref().unwrap_or("")),
            )
            .replace(
                "%to",
                &shell_escape(dialog.to_user.as_deref().unwrap_or("")),
            )
            .replace("%state", &format!("{:?}", dialog.state))
            .replace("%method", &dialog.method);

        self.spawn_command(&cmd);
    }

    /// Fire a quality event if the stream's estimated MOS is below threshold.
    ///
    /// Template variables:
    /// - `%stream_json` — Full stream JSON (via [`super::json::stream_to_json`])
    /// - `%ssrc` — Stream SSRC in hex
    /// - `%mos` — Estimated MOS score
    /// - `%jitter` — Current jitter in ms
    /// - `%loss` — Loss percentage
    pub fn fire_quality_event(&mut self, stream: &RtpStream) {
        let template = match &self.on_quality_cmd {
            Some(cmd) => cmd.clone(),
            None => return,
        };

        // Estimate MOS from jitter and loss (simplified E-model)
        let mos = estimate_mos(stream.jitter, loss_pct(stream));
        if mos >= self.quality_threshold {
            return;
        }

        if !self.check_rate_limit() {
            return;
        }

        let stream_json = super::json::stream_to_json(stream);

        let cmd = template
            .replace("%stream_json", &shell_escape(&stream_json))
            .replace("%ssrc", &format!("0x{:08x}", stream.key.ssrc))
            .replace("%mos", &format!("{mos:.2}"))
            .replace("%jitter", &format!("{:.1}", stream.jitter))
            .replace("%loss", &format!("{:.1}", loss_pct(stream)));

        self.spawn_command(&cmd);
    }

    /// Check and update rate limiting. Returns `true` if execution is allowed.
    fn check_rate_limit(&mut self) -> bool {
        if self.rate_limit == 0 {
            return true;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start);

        // Reset window if more than 1 second has passed
        if elapsed.as_secs() >= 1 {
            self.window_start = now;
            self.exec_count_this_second = 0;
        }

        if self.exec_count_this_second >= self.rate_limit {
            return false;
        }

        true
    }

    /// Spawn a shell command non-blocking.
    fn spawn_command(&mut self, cmd: &str) {
        if self.queue_depth >= MAX_QUEUE_DEPTH {
            warn!(
                "Event exec queue depth ({}) exceeds limit ({}), dropping event",
                self.queue_depth, MAX_QUEUE_DEPTH
            );
            return;
        }

        match Command::new("sh").arg("-c").arg(cmd).spawn() {
            Ok(_child) => {
                self.exec_count_this_second += 1;
                self.queue_depth += 1;
            }
            Err(e) => {
                warn!("Failed to spawn event exec command: {e}");
            }
        }
    }

    /// Decrement the queue depth (call when a child process completes).
    pub fn notify_child_complete(&mut self) {
        self.queue_depth = self.queue_depth.saturating_sub(1);
    }

    /// Return the current queue depth.
    pub fn queue_depth(&self) -> usize {
        self.queue_depth
    }
}

/// Calculate loss percentage for a stream.
fn loss_pct(stream: &RtpStream) -> f64 {
    let total = stream.packet_count + stream.lost_packets;
    if total > 0 {
        (stream.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    }
}

/// Simplified MOS estimation from jitter and loss.
///
/// Uses a simplified E-model approximation:
/// - R-factor starts at 93.2 (G.711 baseline)
/// - Subtract jitter impact (Id = jitter_ms * 0.1)
/// - Subtract loss impact (Ie = loss_pct * 2.5)
/// - Convert to MOS: 1 + 0.035*R + R*(R-60)*(100-R)*7e-6
fn estimate_mos(jitter_ms: f64, loss_pct: f64) -> f64 {
    let r = 93.2 - (jitter_ms * 0.1) - (loss_pct * 2.5);
    let r = r.clamp(0.0, 100.0);

    if r < 1.0 {
        return 1.0;
    }

    let mos = 1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6;
    mos.clamp(1.0, 5.0)
}

/// Simple shell escaping: replace single quotes with escaped form.
fn shell_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::dialog::SipDialog;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn build_sip(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(body);
        msg
    }

    fn make_dialog() -> SipDialog {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: exec-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse");
        SipDialog::new(&msg).expect("should create dialog")
    }

    fn make_stream() -> RtpStream {
        let key = StreamKey {
            ssrc: 0xAABBCCDD,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 100,
            timestamp: 0,
            ssrc: 0xAABBCCDD,
            payload_offset: 12,
        };
        RtpStream::new(key, &hdr, ts())
    }

    #[test]
    fn template_expansion_call_id() {
        // We test by examining the template expansion logic directly
        let template = "echo %call_id";
        let dialog = make_dialog();
        let cmd = template.replace("%call_id", &shell_escape(&dialog.call_id));

        assert_eq!(cmd, "echo exec-test@example.com");
    }

    #[test]
    fn template_expansion_multiple() {
        let template = "notify --from=%from --to=%to --state=%state";
        let dialog = make_dialog();
        let cmd = template
            .replace(
                "%from",
                &shell_escape(dialog.from_user.as_deref().unwrap_or("")),
            )
            .replace(
                "%to",
                &shell_escape(dialog.to_user.as_deref().unwrap_or("")),
            )
            .replace("%state", &format!("{:?}", dialog.state));

        assert!(
            cmd.contains("--from=alice"),
            "should expand from: got {cmd}"
        );
        assert!(cmd.contains("--to=bob"), "should expand to: got {cmd}");
        assert!(
            cmd.contains("--state=Trying"),
            "should expand state: got {cmd}"
        );
    }

    #[test]
    fn rate_limiting_blocks_excess() {
        let mut engine = EventExecEngine::new(Some("true".to_string()), None, 10, 3.0);

        let _dialog = make_dialog();
        let mut fired = 0;

        for _ in 0..15 {
            if engine.check_rate_limit() {
                engine.exec_count_this_second += 1;
                fired += 1;
            }
        }

        assert_eq!(fired, 10, "should only allow 10 execs with rate_limit=10");
    }

    #[test]
    fn mos_estimation_good_quality() {
        // Good conditions: low jitter, no loss
        let mos = estimate_mos(5.0, 0.0);
        assert!(
            mos > 4.0,
            "good conditions should give MOS > 4.0: got {mos}"
        );
    }

    #[test]
    fn mos_estimation_bad_quality() {
        // Bad conditions: high jitter, significant loss
        let mos = estimate_mos(150.0, 15.0);
        assert!(mos < 3.0, "bad conditions should give MOS < 3.0: got {mos}");
    }

    #[test]
    fn shell_escape_handles_quotes() {
        let result = shell_escape("it's a test");
        assert_eq!(result, "it'\\''s a test");
    }

    #[test]
    fn no_cmd_configured_noop() {
        let mut engine = EventExecEngine::new(None, None, 10, 3.0);
        // Should not panic or spawn anything
        engine.fire_dialog_event(&make_dialog());

        let stream = make_stream();
        engine.fire_quality_event(&stream);
    }

    #[test]
    fn queue_depth_tracking() {
        let engine = EventExecEngine::new(None, None, 10, 3.0);
        assert_eq!(engine.queue_depth(), 0);
    }
}
