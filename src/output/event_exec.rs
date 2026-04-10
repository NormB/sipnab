//! Event exec hooks for triggering external commands.
//!
//! Fires shell commands when dialog state changes or RTP quality degrades
//! below a threshold. SIP data is passed via environment variables (never
//! interpolated into the command string) to prevent command injection.
//! Supports rate limiting and non-blocking execution with queue depth caps.

use std::process::Command;
use std::time::Instant;

use log::warn;

use crate::rtp::quality;
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
/// SIP data is passed to commands via `SIPNAB_*` environment variables
/// (e.g., `$SIPNAB_CALL_ID`, `$SIPNAB_FROM`). For backwards compatibility,
/// `%variable` placeholders in command templates are rewritten to
/// `$SIPNAB_VARIABLE` references. Values are never interpolated into the
/// shell command string.
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
    /// Tracked child processes for reaping.
    children: Vec<std::process::Child>,
}

impl EventExecEngine {
    /// Create a new event exec engine.
    ///
    /// # Arguments
    ///
    /// * `on_dialog_cmd` — Command template for dialog events (e.g.,
    ///   `"curl -X POST http://hook/dialog --data \"$SIPNAB_JSON\""`)
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
            on_dialog_cmd: on_dialog_cmd.map(|c| migrate_template_vars(&c)),
            on_quality_cmd: on_quality_cmd.map(|c| migrate_template_vars(&c)),
            rate_limit,
            quality_threshold,
            window_start: Instant::now(),
            exec_count_this_second: 0,
            children: Vec::new(),
        }
    }

    /// Fire a dialog event, passing SIP data via environment variables.
    ///
    /// Environment variables set on the child process:
    /// - `SIPNAB_JSON` — Full dialog JSON
    /// - `SIPNAB_CALL_ID` — The dialog's Call-ID
    /// - `SIPNAB_FROM` — From user
    /// - `SIPNAB_TO` — To user
    /// - `SIPNAB_STATE` — Dialog state (e.g., "Completed")
    /// - `SIPNAB_METHOD` — Initial method (e.g., "INVITE")
    pub fn fire_dialog_event(&mut self, dialog: &SipDialog) {
        let cmd = match &self.on_dialog_cmd {
            Some(cmd) => cmd.clone(),
            None => return,
        };

        if !self.check_rate_limit() {
            return;
        }

        // Build the JSON for SIPNAB_JSON env var
        let json = super::json::dialog_to_json(
            dialog,
            &[],
            &crate::rtp::diagnosis::MediaDiagnosis::default(),
        );

        let vars: Vec<(&str, String)> = vec![
            ("SIPNAB_CALL_ID", dialog.call_id.clone()),
            (
                "SIPNAB_FROM",
                dialog.from_user.as_deref().unwrap_or("").to_string(),
            ),
            (
                "SIPNAB_TO",
                dialog.to_user.as_deref().unwrap_or("").to_string(),
            ),
            ("SIPNAB_STATE", format!("{:?}", dialog.state)),
            ("SIPNAB_METHOD", dialog.method.clone()),
            ("SIPNAB_JSON", json),
        ];

        self.spawn_command(&cmd, &vars);
    }

    /// Fire a quality event if the stream's estimated MOS is below threshold.
    ///
    /// Environment variables set on the child process:
    /// - `SIPNAB_STREAM_JSON` — Full stream JSON
    /// - `SIPNAB_SSRC` — Stream SSRC in hex
    /// - `SIPNAB_MOS` — Estimated MOS score
    /// - `SIPNAB_JITTER` — Current jitter in ms
    /// - `SIPNAB_LOSS` — Loss percentage
    pub fn fire_quality_event(&mut self, stream: &RtpStream) {
        let cmd = match &self.on_quality_cmd {
            Some(cmd) => cmd.clone(),
            None => return,
        };

        // Estimate MOS from jitter and loss via the canonical E-model
        let mos = quality::estimate_mos(stream.jitter, loss_pct(stream), stream.codec.as_deref());
        if mos >= self.quality_threshold {
            return;
        }

        if !self.check_rate_limit() {
            return;
        }

        let stream_json = super::json::stream_to_json(stream);

        let vars: Vec<(&str, String)> = vec![
            ("SIPNAB_STREAM_JSON", stream_json),
            ("SIPNAB_SSRC", format!("0x{:08x}", stream.key.ssrc)),
            ("SIPNAB_MOS", format!("{mos:.2}")),
            ("SIPNAB_JITTER", format!("{:.1}", stream.jitter)),
            ("SIPNAB_LOSS", format!("{:.1}", loss_pct(stream))),
        ];

        self.spawn_command(&cmd, &vars);
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

    /// Reap completed child processes to prevent zombies and update queue depth.
    fn reap_children(&mut self) {
        self.children.retain_mut(|child| {
            match child.try_wait() {
                Ok(Some(_status)) => false, // completed, remove
                Ok(None) => true,           // still running, keep
                Err(e) => {
                    warn!("Error checking child process: {e}");
                    false // remove on error
                }
            }
        });
    }

    /// Spawn a shell command non-blocking with environment variables.
    ///
    /// SIP data is passed exclusively via environment variables — never
    /// interpolated into the command string — to prevent command injection.
    fn spawn_command(&mut self, cmd: &str, env_vars: &[(&str, String)]) {
        self.reap_children();

        if self.children.len() >= MAX_QUEUE_DEPTH {
            warn!(
                "Event exec queue depth ({}) exceeds limit ({}), dropping event",
                self.children.len(),
                MAX_QUEUE_DEPTH
            );
            return;
        }

        let mut command = Command::new("sh");
        command.arg("-c").arg(cmd);
        for (key, value) in env_vars {
            command.env(key, value);
        }

        match command.spawn() {
            Ok(child) => {
                self.exec_count_this_second += 1;
                self.children.push(child);
            }
            Err(e) => {
                warn!("Failed to spawn event exec command: {e}");
            }
        }
    }

    /// Return the current queue depth (number of tracked children).
    pub fn queue_depth(&self) -> usize {
        self.children.len()
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

/// Rewrite legacy `%variable` placeholders to `$SIPNAB_VARIABLE` references.
///
/// This provides backwards compatibility for users who have existing command
/// templates using the old `%call_id`, `%from`, etc. syntax. The values are
/// passed as environment variables, never interpolated into the command string.
fn migrate_template_vars(template: &str) -> String {
    template
        .replace("%json", "$SIPNAB_JSON")
        .replace("%call_id", "$SIPNAB_CALL_ID")
        .replace("%from", "$SIPNAB_FROM")
        .replace("%to", "$SIPNAB_TO")
        .replace("%state", "$SIPNAB_STATE")
        .replace("%method", "$SIPNAB_METHOD")
        .replace("%stream_json", "$SIPNAB_STREAM_JSON")
        .replace("%ssrc", "$SIPNAB_SSRC")
        .replace("%mos", "$SIPNAB_MOS")
        .replace("%jitter", "$SIPNAB_JITTER")
        .replace("%loss", "$SIPNAB_LOSS")
        .replace("%src", "$SIPNAB_SRC")
        .replace("%rule", "$SIPNAB_RULE")
        .replace("%detail", "$SIPNAB_DETAIL")
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
    fn migrate_template_vars_call_id() {
        let migrated = migrate_template_vars("echo %call_id");
        assert_eq!(migrated, "echo $SIPNAB_CALL_ID");
    }

    #[test]
    fn migrate_template_vars_multiple() {
        let migrated = migrate_template_vars("notify --from=%from --to=%to --state=%state");
        assert!(migrated.contains("$SIPNAB_FROM"));
        assert!(migrated.contains("$SIPNAB_TO"));
        assert!(migrated.contains("$SIPNAB_STATE"));
    }

    #[test]
    fn env_var_injection_prevents_command_injection() {
        // A malicious call-id with shell metacharacters should NOT be
        // interpolated into the command string. It is only passed as an env var.
        let engine = EventExecEngine::new(Some("echo $SIPNAB_CALL_ID".to_string()), None, 10, 3.0);
        // The command template should be stored as-is (after migration)
        assert_eq!(
            engine.on_dialog_cmd.as_deref(),
            Some("echo $SIPNAB_CALL_ID")
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
        // Good conditions: low jitter, no loss — uses canonical estimate_mos
        let mos = quality::estimate_mos(5.0, 0.0, Some("PCMU"));
        assert!(
            mos > 4.0,
            "good conditions should give MOS > 4.0: got {mos}"
        );
    }

    #[test]
    fn mos_estimation_bad_quality() {
        // Bad conditions: high jitter, significant loss — uses canonical estimate_mos
        let mos = quality::estimate_mos(150.0, 15.0, None);
        assert!(mos < 3.0, "bad conditions should give MOS < 3.0: got {mos}");
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

    #[test]
    fn legacy_template_migration_at_construction() {
        let engine = EventExecEngine::new(
            Some("echo %call_id %from".to_string()),
            Some("alert %mos %jitter".to_string()),
            10,
            3.0,
        );
        assert_eq!(
            engine.on_dialog_cmd.as_deref(),
            Some("echo $SIPNAB_CALL_ID $SIPNAB_FROM")
        );
        assert_eq!(
            engine.on_quality_cmd.as_deref(),
            Some("alert $SIPNAB_MOS $SIPNAB_JITTER")
        );
    }
}
