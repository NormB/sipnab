//! Rule-based alerting engine with cooldowns and external command execution.
//!
//! The alerting engine evaluates named rules with threshold/window/cooldown
//! parameters and deduplicates alerts per (source IP, rule name) pair.
//!
//! Rule grammar: `<metric>:<threshold>/<window>[:<cooldown>]`
//! - `5xx-rate:10/1m` — 10 events in 1 minute, cooldown auto (2 minutes)
//! - `reg-flood:50/10s:5m` — 50 events in 10 seconds, cooldown 5 minutes
//! - Window suffixes: `s` (seconds), `m` (minutes), `h` (hours)
//! - Default cooldown: window x 2

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use log::warn;

/// A single alerting rule with threshold, window, and cooldown.
#[derive(Debug, Clone)]
pub struct AlertRule {
    /// Rule name (e.g., `"5xx-rate"`, `"reg-flood"`).
    pub name: String,
    /// Number of events required to trigger within the window.
    pub threshold: u32,
    /// Time window for counting events.
    pub window: Duration,
    /// Minimum time between repeated alerts for the same source.
    pub cooldown: Duration,
}

impl AlertRule {
    /// Parse a rule from the grammar `<name>:<threshold>/<window>[:<cooldown>]`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sipnab::security::AlertRule;
    ///
    /// let rule = AlertRule::parse("5xx-rate:10/1m").unwrap();
    /// assert_eq!(rule.name, "5xx-rate");
    /// assert_eq!(rule.threshold, 10);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error string if the rule grammar is invalid.
    pub fn parse(rule_str: &str) -> Result<Self, String> {
        // Split into name:rest
        let (name, rest) = rule_str
            .split_once(':')
            .ok_or_else(|| format!("missing ':' in rule '{rule_str}' — expected <name>:<threshold>/<window>[:<cooldown>]"))?;

        if name.is_empty() {
            return Err(format!("empty rule name in '{rule_str}'"));
        }

        // Check for optional cooldown after the window
        let (threshold_window, cooldown_str) = if let Some((tw, cd)) = rest.split_once(':') {
            (tw, Some(cd))
        } else {
            (rest, None)
        };

        // Split threshold/window
        let (threshold_str, window_str) = threshold_window.split_once('/').ok_or_else(|| {
            format!("missing '/' in rule '{rule_str}' — expected <threshold>/<window>")
        })?;

        let threshold: u32 = threshold_str
            .parse()
            .map_err(|e| format!("invalid threshold '{threshold_str}': {e}"))?;

        let window = parse_duration(window_str)
            .ok_or_else(|| format!("invalid window '{window_str}' — use suffix s/m/h"))?;

        let cooldown = if let Some(cd) = cooldown_str {
            parse_duration(cd)
                .ok_or_else(|| format!("invalid cooldown '{cd}' — use suffix s/m/h"))?
        } else {
            // Default: window x 2
            window * 2
        };

        Ok(AlertRule {
            name: name.to_string(),
            threshold,
            window,
            cooldown,
        })
    }
}

/// Parse a duration string with suffix: `10s`, `5m`, `2h`.
///
/// Returns `None` if the format is invalid.
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_part, suffix) = s.split_at(s.len() - 1);
    let value: u64 = num_part.parse().ok()?;

    match suffix {
        "s" => Some(Duration::from_secs(value)),
        "m" => Some(Duration::from_secs(value * 60)),
        "h" => Some(Duration::from_secs(value * 3600)),
        _ => None,
    }
}

/// Alerting engine that manages rules, cooldowns, and command execution.
pub struct AlertEngine {
    /// Configured alert rules.
    rules: Vec<AlertRule>,
    /// Per (source IP, rule name) cooldown tracking.
    cooldowns: HashMap<(IpAddr, String), Instant>,
    /// Optional external command template to execute on alert.
    exec_cmd: Option<String>,
}

impl AlertEngine {
    /// Create a new alert engine.
    ///
    /// # Arguments
    ///
    /// * `rules` — Alert rules to evaluate.
    /// * `exec_cmd` — Optional command template. Variables `%src`, `%rule`,
    ///   and `%detail` are expanded before execution.
    pub fn new(rules: Vec<AlertRule>, exec_cmd: Option<String>) -> Self {
        Self {
            rules,
            cooldowns: HashMap::new(),
            exec_cmd,
        }
    }

    /// Fire an alert for the given type and source.
    ///
    /// Checks cooldown for the (source, alert_type) pair. If cooled down,
    /// formats the alert, writes to stderr, and optionally executes the
    /// configured command.
    ///
    /// Returns `true` if the alert was actually fired (not suppressed).
    pub fn fire(&mut self, alert_type: &str, src_ip: IpAddr, detail: &str) -> bool {
        let now = Instant::now();
        let key = (src_ip, alert_type.to_string());

        // Find the matching rule's cooldown, or use a default
        let cooldown = self
            .rules
            .iter()
            .find(|r| r.name == alert_type)
            .map(|r| r.cooldown)
            .unwrap_or(Duration::from_secs(60));

        // Check cooldown
        if let Some(last_fired) = self.cooldowns.get(&key)
            && now.duration_since(*last_fired) < cooldown
        {
            return false; // Still in cooldown
        }

        // Record this firing
        self.cooldowns.insert(key, now);

        // Output to stderr
        eprintln!("[ALERT] {alert_type} src={src_ip} {detail}");

        // Execute command if configured
        if let Some(template) = &self.exec_cmd {
            let cmd = template
                .replace("%src", &src_ip.to_string())
                .replace("%rule", alert_type)
                .replace("%detail", detail);

            if let Err(e) = Command::new("sh").arg("-c").arg(&cmd).spawn() {
                warn!("Failed to execute alert command: {e}");
            }
        }

        true
    }

    /// Return a reference to the configured rules.
    pub fn rules(&self) -> &[AlertRule] {
        &self.rules
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    #[test]
    fn parse_rule_basic() {
        let rule = AlertRule::parse("5xx-rate:10/1m").expect("should parse");
        assert_eq!(rule.name, "5xx-rate");
        assert_eq!(rule.threshold, 10);
        assert_eq!(rule.window, Duration::from_secs(60));
        assert_eq!(
            rule.cooldown,
            Duration::from_secs(120),
            "default cooldown should be 2x window"
        );
    }

    #[test]
    fn parse_rule_with_cooldown() {
        let rule = AlertRule::parse("reg-flood:50/10s:5m").expect("should parse");
        assert_eq!(rule.name, "reg-flood");
        assert_eq!(rule.threshold, 50);
        assert_eq!(rule.window, Duration::from_secs(10));
        assert_eq!(rule.cooldown, Duration::from_secs(300));
    }

    #[test]
    fn parse_rule_hours() {
        let rule = AlertRule::parse("slow-scan:100/1h").expect("should parse");
        assert_eq!(rule.window, Duration::from_secs(3600));
        assert_eq!(rule.cooldown, Duration::from_secs(7200));
    }

    #[test]
    fn parse_rule_invalid_no_colon() {
        let result = AlertRule::parse("invalid-rule");
        assert!(result.is_err(), "should fail without colon separator");
    }

    #[test]
    fn parse_rule_invalid_no_slash() {
        let result = AlertRule::parse("bad:10");
        assert!(result.is_err(), "should fail without slash separator");
    }

    #[test]
    fn parse_rule_invalid_threshold() {
        let result = AlertRule::parse("bad:abc/1m");
        assert!(result.is_err(), "should fail with non-numeric threshold");
    }

    #[test]
    fn parse_rule_invalid_window() {
        let result = AlertRule::parse("bad:10/1x");
        assert!(result.is_err(), "should fail with invalid window suffix");
    }

    #[test]
    fn parse_rule_empty_name() {
        let result = AlertRule::parse(":10/1m");
        assert!(result.is_err(), "should fail with empty name");
    }

    #[test]
    fn cooldown_suppresses_second_alert() {
        let rule = AlertRule::parse("test:1/1s:10m").expect("parse");
        let mut engine = AlertEngine::new(vec![rule], None);

        let first = engine.fire("test", test_ip(), "first alert");
        assert!(first, "first alert should fire");

        let second = engine.fire("test", test_ip(), "second alert");
        assert!(!second, "second alert within cooldown should be suppressed");
    }

    #[test]
    fn different_sources_independent_cooldown() {
        let rule = AlertRule::parse("test:1/1s:10m").expect("parse");
        let mut engine = AlertEngine::new(vec![rule], None);

        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert!(engine.fire("test", ip1, "alert from ip1"));
        assert!(
            engine.fire("test", ip2, "alert from ip2"),
            "different source should fire independently"
        );
    }

    #[test]
    fn unknown_rule_uses_default_cooldown() {
        let mut engine = AlertEngine::new(vec![], None);

        let first = engine.fire("unknown-rule", test_ip(), "test");
        assert!(first, "first alert for unknown rule should fire");

        let second = engine.fire("unknown-rule", test_ip(), "test");
        assert!(
            !second,
            "second alert should be suppressed by default cooldown"
        );
    }
}
