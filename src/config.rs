// SPDX-License-Identifier: MIT OR Apache-2.0

//! TOML configuration file loading with cascading search paths.
//!
//! Supports TOML configuration with cascading file search:
//! explicit path > `$SIPNAB_CONFIG` > `~/.config/sipnab/sipnab.toml` >
//! `~/.sipnabrc` > `/etc/sipnab/sipnab.toml`.
//!
//! Unknown keys produce a warning (not a hard error) to allow forward
//! compatibility when configs are shared across versions.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Known valid keys per config section.
///
/// Maps a section name (`""` for the root level, listing the section names
/// themselves) to that section's accepted key names. Built once on first
/// use and cached for the process lifetime; used only by unknown-key
/// detection.
static KNOWN_KEYS: LazyLock<HashMap<&'static str, &'static [&'static str]>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(
        "",
        [
            "capture",
            "display",
            "filter",
            "sip",
            "security",
            "limits",
            "privilege",
            "theme",
            "keybindings",
            "names",
            "crash",
            "media",
        ]
        .as_slice(),
    );
    // [media] describes the PATH being observed, which is neither a capture
    // setting nor a display one. Today it holds the one figure a passive tap
    // cannot measure for itself.
    m.insert("media", ["one_way_delay_ms"].as_slice());
    m.insert(
        "crash",
        ["reports", "backtrace", "report_dir", "core"].as_slice(),
    );
    m.insert(
        "capture",
        [
            "device",
            "node_name",
            "portrange",
            "snaplen",
            "buffer",
            "buffer_budget_mb",
            "no_rtp",
            "promisc",
        ]
        .as_slice(),
    );
    m.insert(
        "display",
        [
            "color",
            "payload_limit",
            "delta_time",
            "visible_columns",
            "from_to",
        ]
        .as_slice(),
    );
    m.insert("filter", ["from", "to", "expression"].as_slice());
    m.insert("sip", ["xcid_headers"].as_slice());
    m.insert(
        "security",
        [
            "kill_scanner",
            "kill_response",
            "fraud_detect",
            "alert",
            "alert_exec",
        ]
        .as_slice(),
    );
    m.insert(
        "limits",
        [
            "dialog_limit",
            "max_streams",
            "max_reassembly",
            "hep_rate_limit",
            "max_header_line",
            "max_headers_per_message",
            "max_messages_per_dialog",
            "max_audio_frames",
            "mcp_max_rows",
        ]
        .as_slice(),
    );
    m.insert("privilege", ["user", "no_priv_drop", "chroot"].as_slice());
    m.insert(
        "names",
        [
            "enabled",
            "reverse_dns",
            "hosts_file",
            "manual",
            "persist_to_config",
        ]
        .as_slice(),
    );
    m.insert(
        "theme",
        [
            "background",
            "foreground",
            "highlight",
            "header",
            "selected",
            "accent",
            "good",
            "warning",
            "bad",
            "muted",
            "border",
        ]
        .as_slice(),
    );
    m.insert(
        "keybindings",
        [
            "quit",
            "help",
            "filter",
            "save",
            "search",
            "settings",
            "pause",
            "autoscroll",
            "extended_flow",
            "clear_calls",
            "column_selector",
        ]
        .as_slice(),
    );
    m
});

/// Accessor for the process-wide [`KNOWN_KEYS`] table; used only by
/// unknown-key detection.
fn known_keys() -> &'static HashMap<&'static str, &'static [&'static str]> {
    &KNOWN_KEYS
}

/// Walk a parsed TOML value and collect every key not in the known set
/// (`key` for root-level, `section.key` within a section).
///
/// Returns an empty vector when `value` is not a table or every key is
/// known. Keys inside an unknown section are not walked (the section
/// itself is already reported). Pure — no logging.
fn collect_unknown_keys(value: &toml::Value) -> Vec<String> {
    let known = known_keys();
    let mut unknown = Vec::new();

    let table = match value.as_table() {
        Some(t) => t,
        None => return unknown,
    };

    let Some(root_keys) = known.get("") else {
        return unknown;
    };
    for key in table.keys() {
        if !root_keys.contains(&key.as_str()) {
            unknown.push(key.clone());
        }
    }

    for (section, val) in table {
        if let Some(section_table) = val.as_table()
            && let Some(valid_keys) = known.get(section.as_str())
        {
            for key in section_table.keys() {
                if !valid_keys.contains(&key.as_str()) {
                    unknown.push(format!("{section}.{key}"));
                }
            }
        }
    }
    unknown
}

/// Walk a parsed TOML value and warn about any keys not in the known set.
///
/// # Side effects
/// Emits one `tracing::warn!` line per unknown key; returns nothing.
fn warn_unknown_keys(value: &toml::Value) {
    for key in collect_unknown_keys(value) {
        tracing::warn!("Unknown config key: {key}");
    }
}

/// Top-level configuration (lenient — ignores unknown fields).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct Config {
    /// Packet capture settings.
    #[serde(default)]
    pub capture: CaptureConfig,
    /// Display and TUI settings.
    #[serde(default)]
    pub display: DisplayConfig,
    /// Filter presets.
    #[serde(default)]
    pub filter: FilterConfig,
    /// SIP protocol handling (dialog correlation, ...).
    #[serde(default)]
    pub sip: SipConfig,
    /// Security detection settings.
    #[serde(default)]
    pub security: SecurityConfig,
    /// Properties of the observed media path — see [`MediaConfig`].
    #[serde(default)]
    pub media: MediaConfig,

    /// Resource limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Privilege dropping settings.
    #[serde(default)]
    pub privilege: PrivilegeConfig,
    /// TUI theme colors.
    #[serde(default)]
    pub theme: ThemeConfig,
    /// TUI key bindings.
    #[serde(default)]
    pub keybindings: KeybindingsConfig,
    /// Address name-resolution settings.
    #[serde(default)]
    pub names: NamesConfig,
    /// Crash handling (panic reports, backtraces, core dumps).
    #[serde(default)]
    pub crash: CrashConfig,
}

/// SIP protocol handling configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct SipConfig {
    /// Header names used for B2BUA leg correlation (sngrep `sip.xcid`).
    /// Defaults to `["X-Call-ID"]` when unset or empty. Set to add
    /// carrier-specific headers, e.g. `["X-Call-ID", "X-CID"]`.
    pub xcid_headers: Option<Vec<String>>,
}

/// Packet capture configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CaptureConfig {
    /// Default network interface.
    pub device: Option<String>,
    /// Name this box reports as, in `capture_identity.node` on every answer.
    ///
    /// Defaults to the system hostname. `--node-name` overrides this, so a
    /// deployed config can name the box while a one-off command relabels it.
    /// Clipped to 64 characters.
    pub node_name: Option<String>,
    /// SIP port range.
    pub portrange: Option<String>,
    /// Snapshot length.
    pub snaplen: Option<u32>,
    /// Kernel buffer size (MiB).
    pub buffer: Option<u32>,
    /// Memory budget (MiB) for the in-flight packet queue between capture and
    /// processing (default 64). Grows under load up to this budget, shrinks when
    /// idle. `--buffer-budget` overrides this.
    pub buffer_budget_mb: Option<u32>,
    /// Disable RTP capture by default.
    pub no_rtp: Option<bool>,
    /// Put the interface into promiscuous mode (default true). `--no-promisc`
    /// overrides this to false.
    pub promisc: Option<bool>,
}

/// Display configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct DisplayConfig {
    /// Color mode ("auto", "always", "never").
    pub color: Option<String>,
    /// Maximum payload bytes to display.
    pub payload_limit: Option<usize>,
    /// Show delta time by default.
    pub delta_time: Option<bool>,
    /// Visible columns in the call list (list of column names).
    ///
    /// Valid names: `"#"`, `"Method"`, `"From"`, `"To"`, `"Source"`,
    /// `"Destination"`, `"State"`, `"Msgs"`, `"Date"`, `"PDD"`, `"Duration"`.
    /// When set, only the listed columns are shown; unlisted columns are hidden.
    /// When unset, all columns are visible (the default).
    pub visible_columns: Option<Vec<String>>,
    /// Default From/To column display mode. One of `"default"`, `"host-port"`,
    /// `"user"`, `"user-host-port"`. Cycled at runtime with the `u` key.
    pub from_to: Option<String>,
}

/// Filter presets.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct FilterConfig {
    /// Default From header filter.
    pub from: Option<String>,
    /// Default To header filter.
    pub to: Option<String>,
    /// Default filter DSL expression.
    pub expression: Option<String>,
}

/// Crash-handling configuration: what happens when sipnab panics.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CrashConfig {
    /// Write a crash-report file on panic (default: true).
    pub reports: Option<bool>,
    /// Include a full backtrace in the crash report (default: true).
    pub backtrace: Option<bool>,
    /// Directory crash reports are written to
    /// (default: `~/.local/state/sipnab`).
    pub report_dir: Option<PathBuf>,
    /// After the report is written: `true` aborts the process so the OS
    /// can produce a core dump (subject to `ulimit -c` / `core_pattern`);
    /// `false` exits cleanly with status 101, suppressing the core
    /// (default: false).
    pub core: Option<bool>,
}

impl CrashConfig {
    /// Effective value of [`Self::reports`].
    pub fn reports_enabled(&self) -> bool {
        self.reports.unwrap_or(true)
    }

    /// Effective value of [`Self::backtrace`].
    pub fn backtrace_enabled(&self) -> bool {
        self.backtrace.unwrap_or(true)
    }

    /// Effective value of [`Self::core`].
    pub fn core_enabled(&self) -> bool {
        self.core.unwrap_or(false)
    }

    /// Effective report directory: the configured one, else
    /// `~/.local/state/sipnab`, else a `sipnab` dir under the system tmp.
    /// Reads `$HOME` for the fallback; does not touch the filesystem.
    pub fn effective_report_dir(&self) -> PathBuf {
        if let Some(ref dir) = self.report_dir {
            return dir.clone();
        }
        match home_dir() {
            Some(home) => home.join(".local").join("state").join("sipnab"),
            None => std::env::temp_dir().join("sipnab"),
        }
    }
}

/// Security detection configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct SecurityConfig {
    /// Enable scanner detection by default.
    pub kill_scanner: Option<bool>,
    /// Kill response code.
    pub kill_response: Option<u16>,
    /// Enable fraud detection by default.
    pub fraud_detect: Option<bool>,
    /// Alert channels.
    pub alert: Option<Vec<String>>,
    /// Command to execute on alert.
    pub alert_exec: Option<String>,
}

/// Properties of the observed media path that sipnab cannot measure itself.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct MediaConfig {
    /// One-way network delay, in milliseconds, for the path this capture sees.
    ///
    /// The single input to MOS that a passive observer cannot obtain: it is
    /// known to the endpoints or to you, and nobody else. Declaring it here
    /// beats an RTCP-reported round trip, because a config file cannot be
    /// changed by a packet on the wire.
    pub one_way_delay_ms: Option<f64>,
}

/// Resource limits.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum tracked dialogs.
    pub dialog_limit: Option<u64>,
    /// Maximum rows in one list-style MCP response (default: 1000).
    pub mcp_max_rows: Option<u64>,
    /// Maximum RTP streams.
    pub max_streams: Option<u64>,
    /// Maximum TCP reassembly sessions.
    pub max_reassembly: Option<u64>,
    /// HEP rate limit.
    pub hep_rate_limit: Option<u64>,
    /// Maximum bytes in a single unfolded SIP header line (default: 8192).
    pub max_header_line: Option<u64>,
    /// Maximum number of SIP headers per message (default: 200).
    pub max_headers_per_message: Option<u64>,
    /// Maximum stored messages per dialog (default: 500).
    pub max_messages_per_dialog: Option<u64>,
    /// Maximum audio frames retained per RTP stream for WAV export (default: 1500).
    pub max_audio_frames: Option<u64>,
}

impl LimitsConfig {
    /// Validate limit values are within sane ranges.
    ///
    /// Unset (`None`) fields are always valid — they fall back to the
    /// built-in defaults.
    ///
    /// # Errors
    /// `crate::Error::ConfigInvalid` when any count limit is 0 or
    /// `max_header_line` is below 256, naming the offending key.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if let Some(0) = self.dialog_limit {
            return Err(crate::Error::ConfigInvalid(
                "[limits] dialog_limit must be > 0".into(),
            ));
        }
        // Rejected rather than read as "unlimited" or "default": both would
        // turn a typo into silent behaviour the operator did not ask for.
        if let Some(0) = self.mcp_max_rows {
            return Err(crate::Error::ConfigInvalid(
                "[limits] mcp_max_rows must be > 0".into(),
            ));
        }
        if let Some(0) = self.max_streams {
            return Err(crate::Error::ConfigInvalid(
                "[limits] max_streams must be > 0".into(),
            ));
        }
        if let Some(0) = self.max_reassembly {
            return Err(crate::Error::ConfigInvalid(
                "[limits] max_reassembly must be > 0".into(),
            ));
        }
        if let Some(v) = self.max_header_line
            && v < 256
        {
            return Err(crate::Error::ConfigInvalid(
                "[limits] max_header_line must be >= 256".into(),
            ));
        }
        if let Some(0) = self.max_headers_per_message {
            return Err(crate::Error::ConfigInvalid(
                "[limits] max_headers_per_message must be > 0".into(),
            ));
        }
        if let Some(0) = self.max_messages_per_dialog {
            return Err(crate::Error::ConfigInvalid(
                "[limits] max_messages_per_dialog must be > 0".into(),
            ));
        }
        if let Some(0) = self.max_audio_frames {
            return Err(crate::Error::ConfigInvalid(
                "[limits] max_audio_frames must be > 0".into(),
            ));
        }
        Ok(())
    }
}

/// Privilege settings.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct PrivilegeConfig {
    /// User to drop privileges to.
    pub user: Option<String>,
    /// Disable privilege dropping.
    pub no_priv_drop: Option<bool>,
    /// Chroot directory.
    pub chroot: Option<String>,
}

/// Address name-resolution settings.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct NamesConfig {
    /// Start with name resolution enabled (offline sources).
    pub enabled: Option<bool>,
    /// Also use reverse DNS (PTR) lookups. Off by default.
    pub reverse_dns: Option<bool>,
    /// `/etc/hosts`-format file of IP -> name mappings to preload.
    pub hosts_file: Option<String>,
    /// Inline IP -> name mappings, loaded at startup (highest-priority manual
    /// layer). Written by the in-TUI `N` dialog when [`Self::persist_to_config`] is on.
    ///
    /// ```toml
    /// [names.manual]
    /// "10.0.0.1" = "sbc-edge"
    /// ```
    pub manual: Option<BTreeMap<String, String>>,
    /// When true, editing a name in the TUI (`N`) also writes the mapping back
    /// into the `[names.manual]` table of the user's sipnabrc, preserving the
    /// rest of the file. Defaults to off (mappings persist to the hosts file).
    pub persist_to_config: Option<bool>,
}

/// TUI theme configuration — semantic color slots.
///
/// Each field accepts a color name (`"red"`, `"cyan"`, `"dark_gray"`) or
/// a hex RGB value (`"#ff8800"`). Unset fields use built-in defaults.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ThemeConfig {
    /// Terminal background (`Reset` = inherit terminal default).
    pub background: Option<String>,
    /// Default text color.
    pub foreground: Option<String>,
    /// Legacy alias for `selected` (kept for backward compat).
    pub highlight: Option<String>,
    /// Status bar, column headers, endpoint labels.
    pub header: Option<String>,
    /// Selected/highlighted row, cursor, focused item.
    pub selected: Option<String>,
    /// Correlation info, PDD, extended flow labels.
    pub accent: Option<String>,
    /// Positive quality, success states (InCall, Registered).
    pub good: Option<String>,
    /// Medium quality, caution states (Ringing, CANCEL).
    pub warning: Option<String>,
    /// Poor quality, failures, errors.
    pub bad: Option<String>,
    /// Separators, pipes, disabled text, timestamps.
    pub muted: Option<String>,
    /// Widget borders, panel frames.
    pub border: Option<String>,
    /// Status bar background band (kept distinct from the terminal
    /// background so the status line stays visible).
    pub status_bg: Option<String>,
}

/// TUI keybinding overrides.
///
/// Each field accepts a key name: single characters (`"q"`, `"/"`),
/// function keys (`"F1"`–`"F12"`), or special names (`"Esc"`, `"Space"`).
/// Unset fields use built-in defaults.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct KeybindingsConfig {
    /// Quit the application (default: `"q"`).
    pub quit: Option<String>,
    /// Show help overlay (default: `"F1"`).
    pub help: Option<String>,
    /// Open filter dialog (default: `"F7"`).
    pub filter: Option<String>,
    /// Save capture (default: `"F2"`).
    pub save: Option<String>,
    /// Activate search (default: `"/"`).
    pub search: Option<String>,
    /// Open settings popup (default: `"F8"`).
    pub settings: Option<String>,
    /// Pause/resume capture (default: `"p"`).
    pub pause: Option<String>,
    /// Toggle autoscroll (default: `"A"`).
    pub autoscroll: Option<String>,
    /// Toggle extended multi-leg flow (default: `"F4"`).
    pub extended_flow: Option<String>,
    /// Clear all calls (default: `"F5"`).
    pub clear_calls: Option<String>,
    /// Open column selector (default: `"F10"`).
    pub column_selector: Option<String>,
}

// ---------------------------------------------------------------------------
// Parse helpers for color and key config values (TUI feature only)
// ---------------------------------------------------------------------------

/// Parse a color name or hex RGB string into a ratatui Color.
///
/// Accepts: `"black"`, `"white"`, `"red"`, `"green"`, `"yellow"`, `"blue"`,
/// `"magenta"`, `"cyan"`, `"gray"`, `"dark_gray"`, `"reset"`, or `"#RRGGBB"`.
/// Names are case-insensitive. Returns `None` for anything unrecognized
/// (the caller keeps its built-in default), logging a `tracing` warning
/// for unknown names.
#[cfg(feature = "tui")]
pub fn parse_color(s: &str) -> Option<ratatui::style::Color> {
    use ratatui::style::Color;
    match s.to_ascii_lowercase().as_str() {
        "black" => Some(Color::Black),
        "white" => Some(Color::White),
        "red" => Some(Color::Red),
        "green" => Some(Color::Green),
        "yellow" => Some(Color::Yellow),
        "blue" => Some(Color::Blue),
        "magenta" => Some(Color::Magenta),
        "cyan" => Some(Color::Cyan),
        "gray" | "grey" => Some(Color::Gray),
        "dark_gray" | "dark_grey" | "darkgray" | "darkgrey" => Some(Color::DarkGray),
        "reset" | "default" => Some(Color::Reset),
        hex if hex.starts_with('#') && hex.len() == 7 => {
            let r = u8::from_str_radix(&hex[1..3], 16).ok()?;
            let g = u8::from_str_radix(&hex[3..5], 16).ok()?;
            let b = u8::from_str_radix(&hex[5..7], 16).ok()?;
            Some(Color::Rgb(r, g, b))
        }
        _ => {
            tracing::warn!("Unknown color value: {s:?}");
            None
        }
    }
}

/// Parse a key name into a crossterm KeyCode.
///
/// Accepts: single characters (`"q"`, `"/"`), function keys (`"F1"`–`"F12"`),
/// or special names (`"Esc"`, `"Space"`, `"Enter"`, `"Tab"`).
/// Returns `None` for anything unrecognized (the caller keeps its built-in
/// default), logging a `tracing` warning in that case.
#[cfg(feature = "tui")]
pub fn parse_keycode(s: &str) -> Option<crossterm::event::KeyCode> {
    use crossterm::event::KeyCode;
    match s {
        "Esc" | "esc" | "Escape" | "escape" => Some(KeyCode::Esc),
        "Space" | "space" => Some(KeyCode::Char(' ')),
        "Enter" | "enter" | "Return" | "return" => Some(KeyCode::Enter),
        "Tab" | "tab" => Some(KeyCode::Tab),
        "Backspace" | "backspace" => Some(KeyCode::Backspace),
        _ if s.len() == 1 => s.chars().next().map(KeyCode::Char),
        _ if s.starts_with('F') || s.starts_with('f') => s[1..]
            .parse::<u8>()
            .ok()
            .filter(|&n| (1..=12).contains(&n))
            .map(KeyCode::F),
        _ => {
            tracing::warn!("Unknown keybinding value: {s:?}");
            None
        }
    }
}

/// The path from which a config was loaded.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// The parsed configuration.
    pub config: Config,
    /// The file path the config was loaded from, if any.
    pub source: Option<PathBuf>,
}

impl Config {
    /// Load configuration from the first available source.
    ///
    /// Search order:
    /// 1. `explicit_path` (from `--config`) — must exist, errors if missing
    /// 2. `$SIPNAB_CONFIG` environment variable
    /// 3. `~/.config/sipnab/sipnab.toml`
    /// 4. `~/.sipnabrc`
    /// 5. `/etc/sipnab/sipnab.toml`
    ///
    /// If `skip_default` is true (from `--no-config`), returns defaults
    /// without searching any files.
    ///
    /// # Arguments
    /// * `explicit_path` - path from `--config`; when set it must exist.
    /// * `skip_default` - `--no-config`: skip all file searching.
    ///
    /// # Returns
    /// The parsed `Config` plus the path it came from (`source: None`
    /// when defaults were used).
    ///
    /// # Errors
    /// The explicit path does not exist, or whichever file was found
    /// cannot be read or parsed as TOML.
    ///
    /// # Side effects
    /// Reads `$SIPNAB_CONFIG` and `$HOME`, probes candidate paths on the
    /// filesystem, reads the chosen file, and emits `tracing` debug lines
    /// about the search; unknown keys in the file are warned about.
    pub fn load(
        explicit_path: Option<&str>,
        skip_default: bool,
    ) -> Result<LoadedConfig, crate::Error> {
        if skip_default {
            tracing::debug!("Config loading skipped (--no-config)");
            return Ok(LoadedConfig {
                config: Config::default(),
                source: None,
            });
        }

        // 1. Explicit path — must exist
        if let Some(path) = explicit_path {
            let p = PathBuf::from(path);
            if !p.exists() {
                return Err(crate::Error::ConfigNotFound {
                    path: p.display().to_string(),
                });
            }
            let config = Self::load_file(&p)?;
            return Ok(LoadedConfig {
                config,
                source: Some(p),
            });
        }

        // 2. $SIPNAB_CONFIG
        if let Ok(env_path) = std::env::var("SIPNAB_CONFIG") {
            let p = PathBuf::from(&env_path);
            if p.exists() {
                let config = Self::load_file(&p)?;
                return Ok(LoadedConfig {
                    config,
                    source: Some(p),
                });
            }
            tracing::debug!(
                "SIPNAB_CONFIG={} does not exist, continuing search",
                env_path
            );
        }

        // 3-5. Default locations
        let candidates = default_config_paths();
        for p in &candidates {
            if p.exists() {
                let config = Self::load_file(p)?;
                return Ok(LoadedConfig {
                    config,
                    source: Some(p.clone()),
                });
            }
        }

        tracing::debug!("No config file found, using defaults");
        Ok(LoadedConfig {
            config: Config::default(),
            source: None,
        })
    }

    /// Keys in `content` that sipnab does not recognize.
    ///
    /// Deserialization is deliberately lenient — an unknown key is ignored so
    /// a config written for a newer version still starts — and the loader only
    /// `warn!`s about them. That leniency is right for a running binary and
    /// wrong for anything checking a config is correct, because "loaded
    /// without error" and "did what it says" are not the same claim: a sample
    /// with `devise` for `device` loads fine and configures nothing.
    ///
    /// This exposes the signal the loader already computes so a caller — the
    /// documented-sample gate, or an operator validating a file — can tell
    /// those two apart.
    ///
    /// # Errors
    /// `content` is not valid TOML.
    pub fn unknown_keys(content: &str) -> Result<Vec<String>, crate::Error> {
        let value: toml::Value =
            toml::from_str(content).map_err(|e| crate::Error::ConfigParse {
                path: "<inline>".to_string(),
                source: e,
            })?;
        Ok(collect_unknown_keys(&value))
    }

    /// Load and parse a single config file.
    ///
    /// Parses TOML into a generic `toml::Value` first, walks the keys against
    /// the known valid set (warning on unknowns), then deserializes leniently
    /// into `Config`.
    ///
    /// # Errors
    /// `crate::Error::ConfigRead` when the file cannot be read;
    /// `crate::Error::ConfigParse` when it is not valid TOML.
    ///
    /// # Side effects
    /// Reads `path` from the filesystem; unknown keys are logged as
    /// warnings via `parse_toml`.
    fn load_file(path: &Path) -> Result<Config, crate::Error> {
        let content = std::fs::read_to_string(path).map_err(|e| crate::Error::ConfigRead {
            path: path.display().to_string(),
            source: e,
        })?;

        Self::parse_toml(&content, Some(path))
    }

    /// Parse TOML content, warn about unknown keys, and deserialize leniently.
    ///
    /// Separated from `load_file` so unit tests can call it without a real
    /// file. `path` is used only for error/annotation display (`<inline>`
    /// when `None`).
    ///
    /// # Errors
    /// `crate::Error::ConfigParse` when `content` is not valid TOML or does
    /// not deserialize into `Config`.
    ///
    /// # Side effects
    /// Emits a `tracing` warning per unknown key.
    fn parse_toml(content: &str, path: Option<&Path>) -> Result<Config, crate::Error> {
        let display = path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<inline>".to_string());

        // Parse into a generic TOML value to walk keys. Use `from_str` (full
        // document) rather than `str::parse`, which in toml 1.x parses a single
        // value expression (so `[capture]` would be read as an array).
        let value: toml::Value =
            toml::from_str(content).map_err(|e| crate::Error::ConfigParse {
                path: display.clone(),
                source: e,
            })?;

        warn_unknown_keys(&value);

        // Deserialize leniently into Config from the already-parsed value
        // rather than re-parsing the string a second time.
        value.try_into().map_err(|e| crate::Error::ConfigParse {
            path: display,
            source: e,
        })
    }

    /// Dump the effective configuration as TOML.
    ///
    /// Used by `--dump-config` to show what sipnab would use.
    ///
    /// # Errors
    /// `crate::Error::ConfigSerialize` when TOML serialization fails.
    pub fn dump(&self) -> Result<String, crate::Error> {
        toml::to_string_pretty(self).map_err(|e| crate::Error::ConfigSerialize(e.to_string()))
    }
}

/// Surgically update the `[names.manual]` table of a sipnabrc document.
///
/// Parses `existing` (the current file contents; may be empty), replaces the
/// `[names.manual]` table with `entries` (IP string → name), and returns the
/// new document text with all comments, key ordering, and other sections
/// preserved. The previous manual mappings are fully replaced so deletions
/// propagate.
///
/// IP keys are emitted as quoted strings because they contain `.`/`:`, which
/// would otherwise be parsed as dotted (nested) keys.
///
/// # Errors
/// `crate::Error::ConfigInvalid` when `existing` is not valid TOML or
/// `[names]` exists but is not a table. Pure — no filesystem access.
pub fn upsert_manual_mappings(
    existing: &str,
    entries: &[(String, String)],
) -> Result<String, crate::Error> {
    use toml_edit::{DocumentMut, Item, Table, value};

    let mut doc = existing
        .parse::<DocumentMut>()
        .map_err(|e| crate::Error::ConfigInvalid(format!("sipnabrc is not valid TOML: {e}")))?;

    // Ensure [names] exists and is a table.
    if doc.get("names").is_none() {
        doc["names"] = Item::Table(Table::new());
    }
    let names = doc["names"]
        .as_table_mut()
        .ok_or_else(|| crate::Error::ConfigInvalid("[names] is not a table".into()))?;

    // Rebuild the manual sub-table from scratch so removed mappings disappear.
    let mut manual = Table::new();
    for (ip, name) in entries {
        manual[ip.as_str()] = value(name.as_str());
    }
    names["manual"] = Item::Table(manual);

    Ok(doc.to_string())
}

/// Surgically set `[display] visible_columns` in a sipnabrc document.
///
/// Parses `existing` (may be empty), writes `columns` (ordered column labels)
/// as `[display] visible_columns`, and returns the new document text with all
/// comments, key ordering, and other sections preserved. The previous value is
/// fully replaced.
///
/// # Errors
/// `crate::Error::ConfigInvalid` when `existing` is not valid TOML or
/// `[display]` exists but is not a table. Pure — no filesystem access.
pub fn upsert_display_columns(existing: &str, columns: &[String]) -> Result<String, crate::Error> {
    use toml_edit::{Array, DocumentMut, Item, Table, value};

    let mut doc = existing
        .parse::<DocumentMut>()
        .map_err(|e| crate::Error::ConfigInvalid(format!("sipnabrc is not valid TOML: {e}")))?;

    if doc.get("display").is_none() {
        doc["display"] = Item::Table(Table::new());
    }
    let display = doc["display"]
        .as_table_mut()
        .ok_or_else(|| crate::Error::ConfigInvalid("[display] is not a table".into()))?;

    let mut arr = Array::new();
    for c in columns {
        arr.push(c.as_str());
    }
    display["visible_columns"] = value(arr);

    Ok(doc.to_string())
}

/// Write `contents` to the sipnabrc at `path` atomically (native builds) so an
/// interrupted or failing write never truncates the operator's existing config,
/// and a symlink at `path` is replaced rather than followed onto a victim file.
///
/// Uses [`crate::capture::atomic::write_atomic`] (temp file in the same
/// directory + `rename`, which replaces a symlink at the target rather than
/// following it — CWE-59/CWE-377). That helper depends on `tempfile` (a
/// `native` dep); non-native builds, which have no config-writing entry point,
/// fall back to a plain write.
fn write_sipnabrc_atomic(path: &Path, contents: &str) -> Result<(), crate::Error> {
    let result = {
        #[cfg(feature = "native")]
        {
            crate::capture::atomic::write_atomic(path, |w| {
                std::io::Write::write_all(w, contents.as_bytes())
            })
        }
        #[cfg(not(feature = "native"))]
        {
            std::fs::write(path, contents)
        }
    };
    result.map_err(|e| crate::Error::ConfigInvalid(format!("write {}: {e}", path.display())))
}

/// Write the current visible column layout into `[display] visible_columns` of
/// the sipnabrc at `path`, preserving the rest of the file (see
/// [`upsert_display_columns`]). Creates the file and parent directory if needed.
///
/// # Errors
/// The existing file is invalid TOML, the parent directory cannot be
/// created, or the write fails.
///
/// # Side effects
/// Reads `path` (missing file treated as empty), creates its parent
/// directory, and rewrites the file atomically (temp-in-dir + rename via
/// [`crate::capture::atomic::write_atomic`] in native builds).
pub fn write_display_columns_file(path: &Path, columns: &[String]) -> Result<(), crate::Error> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let updated = upsert_display_columns(&existing, columns)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            crate::Error::ConfigInvalid(format!("create {}: {e}", parent.display()))
        })?;
    }
    write_sipnabrc_atomic(path, &updated)
}

/// Return the default config file search paths (items 3-5 of the search
/// order): the two `$HOME`-relative locations (omitted when `$HOME` is
/// unset), then `/etc/sipnab/sipnab.toml`. Reads `$HOME`; does not probe
/// the filesystem.
fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = home_dir() {
        paths.push(home.join(".config").join("sipnab").join("sipnab.toml"));
        paths.push(home.join(".sipnabrc"));
    }

    paths.push(PathBuf::from("/etc/sipnab/sipnab.toml"));
    paths
}

/// Get the user's home directory from `$HOME`, or `None` when unset.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// The user's preferred sipnabrc path (`~/.config/sipnab/sipnab.toml`), used as
/// the write target when persisting name mappings into the config.
/// `None` when `$HOME` is unset.
pub fn default_user_config_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".config").join("sipnab").join("sipnab.toml"))
}

/// Write the current manual name mappings into the `[names.manual]` table of the
/// sipnabrc at `path`, preserving the rest of the file (see
/// [`upsert_manual_mappings`]). Creates the file and parent directory if needed.
///
/// # Errors
/// The existing file is invalid TOML, the parent directory cannot be
/// created, or the write fails.
///
/// # Side effects
/// Reads `path` (missing file treated as empty), creates its parent
/// directory, and rewrites the file atomically (temp-in-dir + rename via
/// [`crate::capture::atomic::write_atomic`] in native builds).
pub fn write_manual_mappings_file(
    path: &Path,
    entries: &[(String, String)],
) -> Result<(), crate::Error> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let updated = upsert_manual_mappings(&existing, entries)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            crate::Error::ConfigInvalid(format!("create {}: {e}", parent.display()))
        })?;
    }
    write_sipnabrc_atomic(path, &updated)
}

/// Unit tests for config loading, TOML parsing, surgical sipnabrc
/// updates, unknown-key detection, and limits validation.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ── Atomic, symlink-safe sipnabrc writes (P2 item 3) ────────────────

    /// `write_display_columns_file` writes the requested columns and leaves no
    /// `.sipnab-tmp-*` temp litter behind (the atomic helper's temp file is
    /// renamed into place, not left in the directory).
    #[test]
    fn write_display_columns_file_is_atomic_no_temp_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sipnabrc");
        write_display_columns_file(&path, &["method".into(), "from".into()]).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        let cfg: Config = toml::from_str(&written).unwrap();
        assert_eq!(
            cfg.display.visible_columns,
            Some(vec!["method".to_string(), "from".to_string()])
        );

        let litter: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".sipnab-tmp-"))
            .collect();
        assert!(litter.is_empty(), "temp file left behind: {litter:?}");
    }

    /// A symlink at the target path must NOT be followed: the write replaces the
    /// link with a real file (atomic temp-in-dir + rename) instead of writing
    /// through it onto the victim (CWE-59). Native-only: the non-native fallback
    /// is a plain `fs::write`, which has no atomic helper.
    #[test]
    #[cfg(all(unix, feature = "native"))]
    fn write_display_columns_file_does_not_follow_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.toml");
        std::fs::write(&victim, "# do not touch\n").unwrap();
        let link = dir.path().join("sipnabrc");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        write_display_columns_file(&link, &["method".into()]).unwrap();

        // The victim behind the link is untouched.
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "# do not touch\n",
            "the symlink target must not be written through"
        );
        // The path itself is now a regular file (the link was replaced).
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            meta.file_type().is_file(),
            "target should be a regular file, not a symlink"
        );
        let cfg: Config = toml::from_str(&std::fs::read_to_string(&link).unwrap()).unwrap();
        assert_eq!(
            cfg.display.visible_columns,
            Some(vec!["method".to_string()])
        );
    }

    /// Same symlink-no-follow guarantee for the manual-mappings writer.
    #[test]
    #[cfg(all(unix, feature = "native"))]
    fn write_manual_mappings_file_does_not_follow_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.toml");
        std::fs::write(&victim, "# do not touch\n").unwrap();
        let link = dir.path().join("sipnabrc");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        write_manual_mappings_file(&link, &[("10.0.0.1".into(), "pbx".into())]).unwrap();

        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "# do not touch\n",
            "the symlink target must not be written through"
        );
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_file());
    }

    /// `Config::default()` leaves every optional field unset.
    #[test]
    fn default_config_is_valid() {
        let config = Config::default();
        assert!(config.capture.device.is_none());
        assert!(config.display.color.is_none());
        assert!(config.security.kill_scanner.is_none());
    }

    /// A single-key TOML file parses; every other field stays default.
    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
[capture]
device = "eth0"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.capture.device.as_deref(), Some("eth0"));
        assert!(config.display.color.is_none());
        assert!(config.display.from_to.is_none());
    }

    /// `upsert_manual_mappings` keeps comments and unrelated sections,
    /// quotes IP keys, and round-trips through the typed config.
    #[test]
    fn upsert_manual_preserves_comments_and_other_sections() {
        let existing = r#"# my sipnab config
[capture]
device = "eth0"  # capture NIC

[names]
enabled = true
"#;
        let entries = vec![
            ("10.0.0.1".to_string(), "sbc-edge".to_string()),
            ("2001:db8::1".to_string(), "core6".to_string()),
        ];
        let out = upsert_manual_mappings(existing, &entries).expect("valid toml");
        // Comments and the unrelated section survive.
        assert!(out.contains("# my sipnab config"));
        assert!(out.contains("device = \"eth0\"  # capture NIC"));
        assert!(out.contains("enabled = true"));
        // The manual table is present with quoted IP keys (dots/colons need quoting).
        assert!(out.contains("[names.manual]"), "got:\n{out}");
        assert!(out.contains(r#""10.0.0.1" = "sbc-edge""#), "got:\n{out}");
        assert!(out.contains(r#""2001:db8::1" = "core6""#), "got:\n{out}");
        // Re-parsing yields the same mappings (round-trip).
        let cfg: Config = toml::from_str(&out).unwrap();
        let manual = cfg.names.manual.unwrap();
        assert_eq!(manual.get("10.0.0.1").map(String::as_str), Some("sbc-edge"));
        assert_eq!(manual.get("2001:db8::1").map(String::as_str), Some("core6"));
    }

    /// An empty document gains `[names.manual]`; existing entries are
    /// fully replaced so deletions propagate.
    #[test]
    fn upsert_manual_into_empty_and_replaces_existing() {
        // Empty input → creates [names.manual] from scratch.
        let out =
            upsert_manual_mappings("", &[("1.2.3.4".to_string(), "host".to_string())]).unwrap();
        assert!(out.contains("[names.manual]"));
        assert!(out.contains(r#""1.2.3.4" = "host""#));

        // Existing manual entries are fully replaced by the new set.
        let existing = "[names.manual]\n\"9.9.9.9\" = \"old\"\n";
        let out = upsert_manual_mappings(existing, &[("1.1.1.1".to_string(), "new".to_string())])
            .unwrap();
        assert!(out.contains(r#""1.1.1.1" = "new""#));
        assert!(
            !out.contains("9.9.9.9"),
            "stale entries must be removed:\n{out}"
        );
    }

    /// Malformed existing TOML is rejected rather than clobbered.
    #[test]
    fn upsert_manual_rejects_invalid_toml() {
        assert!(upsert_manual_mappings("this is = = not toml", &[]).is_err());
    }

    // ── display column persistence (F10 save) ────────────────────────

    /// `upsert_display_columns` keeps comments and unrelated sections and
    /// round-trips through the typed config.
    #[test]
    fn upsert_display_columns_preserves_other_sections() {
        let existing = "# my config\n[capture]\nsnaplen = 1500\n";
        let cols = vec!["#".to_string(), "Method".to_string(), "From".to_string()];
        let out = upsert_display_columns(existing, &cols).expect("valid toml");
        // Unrelated section + comment survive.
        assert!(out.contains("# my config"));
        assert!(out.contains("snaplen = 1500"));
        // Round-trips into the typed config.
        let cfg: Config = toml::from_str(&out).unwrap();
        assert_eq!(
            cfg.display.visible_columns.as_deref(),
            Some(cols.as_slice())
        );
        assert_eq!(cfg.capture.snaplen, Some(1500));
    }

    /// An existing `visible_columns` value is fully replaced, not merged.
    #[test]
    fn upsert_display_columns_replaces_existing() {
        let existing = "[display]\nvisible_columns = [\"#\", \"State\"]\n";
        let cols = vec!["Method".to_string(), "Duration".to_string()];
        let out = upsert_display_columns(existing, &cols).unwrap();
        let cfg: Config = toml::from_str(&out).unwrap();
        assert_eq!(
            cfg.display.visible_columns.as_deref(),
            Some(cols.as_slice())
        );
        assert!(
            !out.contains("State"),
            "stale columns must be replaced:\n{out}"
        );
    }

    /// Malformed existing TOML is rejected rather than clobbered.
    #[test]
    fn upsert_display_columns_rejects_invalid_toml() {
        assert!(upsert_display_columns("this is = = not toml", &[]).is_err());
    }

    /// Hiding every column persists as an empty list, not a missing key.
    #[test]
    fn upsert_display_columns_empty_writes_empty_array() {
        // Hiding every column persists as an empty list, not a missing key.
        let out = upsert_display_columns("", &[]).unwrap();
        let cfg: Config = toml::from_str(&out).unwrap();
        assert_eq!(cfg.display.visible_columns.as_deref(), Some([].as_slice()));
    }

    /// `write_display_columns_file` creates nested parent dirs, persists
    /// the columns, and a second write replaces the set.
    #[test]
    fn write_display_columns_file_creates_dirs_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/sipnab.toml");
        let cols = vec![
            "#".to_string(),
            "Method".to_string(),
            "Duration".to_string(),
        ];
        write_display_columns_file(&path, &cols).unwrap();
        let cfg = Config::load(Some(path.to_str().unwrap()), false)
            .unwrap()
            .config;
        assert_eq!(
            cfg.display.visible_columns.as_deref(),
            Some(cols.as_slice())
        );

        // A second write replaces the set.
        let cols2 = vec!["From".to_string(), "To".to_string()];
        write_display_columns_file(&path, &cols2).unwrap();
        let cfg = Config::load(Some(path.to_str().unwrap()), false)
            .unwrap()
            .config;
        assert_eq!(
            cfg.display.visible_columns.as_deref(),
            Some(cols2.as_slice())
        );
    }

    /// `write_manual_mappings_file` creates nested parent dirs, persists
    /// the mappings, and a second write replaces the set (deletions
    /// propagate).
    #[test]
    fn write_manual_mappings_file_creates_dirs_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        // Nested path exercises parent-dir creation.
        let path = dir.path().join("nested/sipnab.toml");
        write_manual_mappings_file(&path, &[("10.0.0.1".to_string(), "sbc".to_string())]).unwrap();
        let cfg = Config::load(Some(path.to_str().unwrap()), false)
            .unwrap()
            .config;
        assert_eq!(
            cfg.names
                .manual
                .as_ref()
                .unwrap()
                .get("10.0.0.1")
                .map(String::as_str),
            Some("sbc")
        );

        // A second write replaces the set (deletion propagates).
        write_manual_mappings_file(&path, &[("10.0.0.2".to_string(), "core".to_string())]).unwrap();
        let cfg = Config::load(Some(path.to_str().unwrap()), false)
            .unwrap()
            .config;
        let m = cfg.names.manual.unwrap();
        assert_eq!(m.get("10.0.0.2").map(String::as_str), Some("core"));
        assert!(!m.contains_key("10.0.0.1"));
    }

    /// A quoted-IP `[names.manual]` table deserializes into the map.
    #[test]
    fn parse_names_manual_table() {
        let toml_str = r#"
[names.manual]
"10.0.0.1" = "sbc"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let manual = config.names.manual.expect("manual table");
        assert_eq!(manual.get("10.0.0.1").map(String::as_str), Some("sbc"));
    }

    /// `[capture] buffer_budget_mb` deserializes.
    #[test]
    fn parse_capture_buffer_budget() {
        let toml_str = r#"
[capture]
buffer_budget_mb = 128
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.capture.buffer_budget_mb, Some(128));
    }

    /// `[display] from_to` deserializes as the raw mode string.
    #[test]
    fn parse_display_from_to() {
        let toml_str = r#"
[display]
from_to = "user-host-port"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.display.from_to.as_deref(), Some("user-host-port"));
    }

    /// A config exercising every section deserializes with all values
    /// landing in the right fields.
    #[test]
    fn parse_full_toml() {
        let toml_str = r##"
[capture]
device = "eth0"
portrange = "5060-5080"
snaplen = 65535
buffer = 16
no_rtp = false

[display]
color = "always"
payload_limit = 4096
delta_time = true

[filter]
from = "alice"
to = "bob"
expression = "method == INVITE"

[security]
kill_scanner = true
kill_response = 403
fraud_detect = false
alert = ["syslog", "json"]
alert_exec = "/usr/local/bin/alert.sh"

[limits]
dialog_limit = 50000
max_streams = 10000
max_reassembly = 5000
hep_rate_limit = 25000

[privilege]
user = "sipnab"
no_priv_drop = false
chroot = "/var/lib/sipnab"

[theme]
background = "#000000"
foreground = "#ffffff"
highlight = "#ff0000"

[keybindings]
quit = "q"
help = "?"
filter = "/"
"##;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.capture.device.as_deref(), Some("eth0"));
        assert_eq!(config.capture.portrange.as_deref(), Some("5060-5080"));
        assert_eq!(config.capture.snaplen, Some(65535));
        assert_eq!(config.display.color.as_deref(), Some("always"));
        assert_eq!(config.display.payload_limit, Some(4096));
        assert_eq!(config.security.kill_scanner, Some(true));
        assert_eq!(config.security.kill_response, Some(403));
        assert_eq!(config.limits.dialog_limit, Some(50000));
        assert_eq!(config.privilege.user.as_deref(), Some("sipnab"));
        assert_eq!(config.theme.background.as_deref(), Some("#000000"));
        assert_eq!(config.theme.highlight.as_deref(), Some("#ff0000"));
        assert_eq!(config.keybindings.quit.as_deref(), Some("q"));
        assert_eq!(config.keybindings.help.as_deref(), Some("?"));
    }

    /// `--no-config` (skip_default) returns pure defaults with no source.
    #[test]
    fn skip_default_returns_empty() {
        let loaded = Config::load(None, true).unwrap();
        assert!(loaded.source.is_none());
        assert_eq!(loaded.config, Config::default());
    }

    /// An explicit `--config` path that does not exist is a hard error.
    #[test]
    fn missing_explicit_file_errors() {
        let result = Config::load(Some("/nonexistent/sipnab.toml"), false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    /// An explicit existing path loads and is reported as the source.
    #[test]
    fn explicit_path_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "[capture]\ndevice = \"lo\"").unwrap();

        let loaded = Config::load(Some(path.to_str().unwrap()), false).unwrap();
        assert_eq!(loaded.config.capture.device.as_deref(), Some("lo"));
        assert_eq!(loaded.source.unwrap(), path);
    }

    /// Every documented `[crash]` key must be known — a valid section
    /// producing a spurious "Unknown config key: crash" warning trains
    /// users to ignore the warning entirely.
    #[test]
    fn crash_section_keys_are_known() {
        let toml_str =
            "[crash]\nreports = true\nbacktrace = true\nreport_dir = \"/tmp/x\"\ncore = false\n";
        let value: toml::Value = toml::from_str(toml_str).unwrap();
        assert_eq!(
            collect_unknown_keys(&value),
            Vec::<String>::new(),
            "valid [crash] section must not be flagged"
        );
        // And it actually parses into the config.
        let config = Config::parse_toml(toml_str, None).unwrap();
        assert_eq!(config.crash.reports, Some(true));
        assert_eq!(config.crash.core, Some(false));
    }

    /// A typo inside [crash] must still be flagged — with the section
    /// known, detection now reaches the individual keys.
    #[test]
    fn crash_section_typo_is_flagged() {
        let value: toml::Value = toml::from_str("[crash]\nbogus = 1\n").unwrap();
        assert_eq!(
            collect_unknown_keys(&value),
            vec!["crash.bogus".to_string()]
        );
    }

    /// The `[sip]` section and the `[capture] promisc` key are valid config the
    /// code actually reads; neither may be flagged as unknown, or the warning
    /// trains users to ignore it.
    #[test]
    fn sip_section_and_capture_promisc_are_known() {
        let toml_str = "[sip]\nxcid_headers = [\"X-CID\"]\n[capture]\npromisc = false\n";
        let value: toml::Value = toml::from_str(toml_str).unwrap();
        assert_eq!(
            collect_unknown_keys(&value),
            Vec::<String>::new(),
            "valid [sip] section and [capture] promisc must not be flagged"
        );
        // And they actually parse into the config.
        let config = Config::parse_toml(toml_str, None).unwrap();
        assert_eq!(
            config.sip.xcid_headers.as_deref(),
            Some(["X-CID".to_string()].as_slice())
        );
        assert_eq!(config.capture.promisc, Some(false));
    }

    /// The config key is READ, not merely accepted. A key that parses and is
    /// then ignored is the defect this tree has hunted repeatedly.
    #[test]
    fn the_capture_node_name_key_is_parsed() {
        let toml_str = "[capture]\nnode_name = \"sbc-edge-1\"\n";
        let config: Config = toml::from_str(toml_str).expect("parses");
        assert_eq!(config.capture.node_name.as_deref(), Some("sbc-edge-1"));
    }

    /// An unknown key under [capture] is still rejected — adding node_name to
    /// the registry must not have opened the section up.
    #[test]
    fn an_unknown_capture_key_is_still_refused() {
        let toml_str = "[capture]\nnode_nam = \"typo\"\n";
        let parsed: Result<Config, _> = toml::from_str(toml_str);
        // Whether it errors or is caught by the key registry, a typo must not
        // silently become a working config.
        if let Ok(c) = parsed {
            assert!(
                c.capture.node_name.is_none(),
                "a misspelled key must not set the node name"
            );
        }
    }

    /// With `[sip]` now a known section, a typo inside it must still be flagged
    /// (the fix must not turn the section into a wildcard).
    #[test]
    fn sip_section_typo_is_flagged() {
        let value: toml::Value = toml::from_str("[sip]\nbogus = 1\n").unwrap();
        assert_eq!(collect_unknown_keys(&value), vec!["sip.bogus".to_string()]);
    }

    /// An unknown key still parses successfully (lenient loading), via
    /// both string and file-based paths.
    #[test]
    fn unknown_keys_warn_but_succeed() {
        // Unknown key within a section should parse successfully (lenient)
        // and the warn_unknown_keys function should detect it.
        let toml_str = "[capture]\ndevice = \"lo\"\nbogus = true\n";
        let config = Config::parse_toml(toml_str, None).unwrap();
        assert_eq!(config.capture.device.as_deref(), Some("lo"));

        // Also verify via file-based loading
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "[capture]\ndevice = \"lo\"\nbogus = true").unwrap();

        let loaded = Config::load(Some(path.to_str().unwrap()), false).unwrap();
        assert_eq!(loaded.config.capture.device.as_deref(), Some("lo"));
    }

    /// `parse_color` maps names, grey/gray variants, reset, and hex RGB;
    /// unknown names yield `None`.
    #[cfg(feature = "tui")]
    #[test]
    fn parse_color_names() {
        use ratatui::style::Color;
        assert_eq!(parse_color("red"), Some(Color::Red));
        assert_eq!(parse_color("cyan"), Some(Color::Cyan));
        assert_eq!(parse_color("dark_gray"), Some(Color::DarkGray));
        assert_eq!(parse_color("darkgrey"), Some(Color::DarkGray));
        assert_eq!(parse_color("reset"), Some(Color::Reset));
        assert_eq!(parse_color("#ff8800"), Some(Color::Rgb(255, 136, 0)));
        assert_eq!(parse_color("bogus"), None);
    }

    /// `parse_keycode` maps chars, function keys, and special names;
    /// unknown names yield `None`.
    #[cfg(feature = "tui")]
    #[test]
    fn parse_keycode_values() {
        use crossterm::event::KeyCode;
        assert_eq!(parse_keycode("q"), Some(KeyCode::Char('q')));
        assert_eq!(parse_keycode("/"), Some(KeyCode::Char('/')));
        assert_eq!(parse_keycode("F1"), Some(KeyCode::F(1)));
        assert_eq!(parse_keycode("F12"), Some(KeyCode::F(12)));
        assert_eq!(parse_keycode("Esc"), Some(KeyCode::Esc));
        assert_eq!(parse_keycode("Space"), Some(KeyCode::Char(' ')));
        assert_eq!(parse_keycode("bogus_key"), None);
    }

    /// `[display] visible_columns` deserializes as an ordered list.
    #[test]
    fn parse_visible_columns() {
        let toml_str = r##"
[display]
visible_columns = ["#", "Method", "From", "To", "State"]
"##;
        let config: Config = toml::from_str(toml_str).unwrap();
        let cols = config.display.visible_columns.as_ref().unwrap();
        assert_eq!(cols.len(), 5);
        assert_eq!(cols[0], "#");
        assert_eq!(cols[1], "Method");
        assert_eq!(cols[4], "State");
    }

    /// An absent `visible_columns` stays `None` (all columns visible).
    #[test]
    fn visible_columns_absent_is_none() {
        let toml_str = "[display]\ncolor = \"auto\"\n";
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.display.visible_columns.is_none());
    }

    /// `[sip] xcid_headers` deserializes as an ordered list.
    #[test]
    fn sip_xcid_headers_parse() {
        let toml_str = "[sip]\nxcid_headers = [\"X-Call-ID\", \"X-CID\"]\n";
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.sip.xcid_headers.as_deref(),
            Some(["X-Call-ID".to_string(), "X-CID".to_string()].as_slice())
        );
    }

    /// An absent `[sip] xcid_headers` stays `None` (built-in default).
    #[test]
    fn sip_xcid_headers_absent_is_none() {
        let config: Config = toml::from_str("[capture]\nsnaplen = 1500\n").unwrap();
        assert!(config.sip.xcid_headers.is_none());
    }

    /// The semantic theme slots (header/selected/accent/...) deserialize.
    #[test]
    fn parse_theme_with_new_fields() {
        let toml_str = r##"
[theme]
header = "green"
selected = "#ffaa00"
accent = "magenta"
good = "green"
warning = "yellow"
bad = "red"
muted = "dark_gray"
border = "white"
"##;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.theme.header.as_deref(), Some("green"));
        assert_eq!(config.theme.selected.as_deref(), Some("#ffaa00"));
        assert_eq!(config.theme.muted.as_deref(), Some("dark_gray"));
    }

    /// The full keybinding override set deserializes.
    #[test]
    fn parse_keybindings_with_new_fields() {
        let toml_str = r#"
[keybindings]
quit = "x"
save = "F2"
search = "/"
settings = "F8"
pause = "p"
autoscroll = "A"
extended_flow = "F4"
clear_calls = "F5"
column_selector = "F10"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.keybindings.quit.as_deref(), Some("x"));
        assert_eq!(config.keybindings.save.as_deref(), Some("F2"));
        assert_eq!(config.keybindings.settings.as_deref(), Some("F8"));
    }

    // ── LimitsConfig validation tests ──────────────────────────────────

    /// All-unset limits (defaults) pass validation.
    #[test]
    fn limits_default_validates() {
        let limits = LimitsConfig::default();
        assert!(limits.validate().is_ok());
    }

    /// A fully populated set of sane limit values passes validation.
    /// The key parses, is registered, and 0 is refused by name.
    ///
    /// Registration is not a formality: an unregistered key still parses and
    /// still works, but warns "Unknown config key" at every start, and this
    /// tree's own note says a spurious warning on valid config "trains users
    /// to ignore the warning entirely".
    #[test]
    fn mcp_max_rows_parses_is_registered_and_rejects_zero() {
        let cfg: Config = toml::from_str("[limits]\nmcp_max_rows = 250\n").expect("valid");
        assert_eq!(cfg.limits.mcp_max_rows, Some(250));
        assert!(
            Config::unknown_keys("[limits]\nmcp_max_rows = 250\n")
                .expect("scan")
                .is_empty(),
            "mcp_max_rows must be registered, or every user of it is warned at"
        );
        let zero: Config = toml::from_str("[limits]\nmcp_max_rows = 0\n").expect("parses");
        let err = zero.limits.validate().expect_err("0 must be rejected");
        assert!(
            err.to_string().contains("mcp_max_rows"),
            "error must name the key"
        );
    }

    #[test]
    fn limits_valid_values() {
        let limits = LimitsConfig {
            dialog_limit: Some(50000),
            max_streams: Some(10000),
            max_reassembly: Some(5000),
            hep_rate_limit: Some(25000),
            max_header_line: Some(8192),
            max_headers_per_message: Some(200),
            max_messages_per_dialog: Some(500),
            max_audio_frames: Some(1500),
            mcp_max_rows: Some(1000),
        };
        assert!(limits.validate().is_ok());
    }

    /// `dialog_limit = 0` is rejected, naming the key.
    #[test]
    fn limits_zero_dialog_limit_rejected() {
        let limits = LimitsConfig {
            dialog_limit: Some(0),
            ..Default::default()
        };
        let err = limits.validate().unwrap_err();
        assert!(err.to_string().contains("dialog_limit"));
    }

    /// `max_streams = 0` is rejected, naming the key.
    #[test]
    fn limits_zero_max_streams_rejected() {
        let limits = LimitsConfig {
            max_streams: Some(0),
            ..Default::default()
        };
        let err = limits.validate().unwrap_err();
        assert!(err.to_string().contains("max_streams"));
    }

    /// `max_reassembly = 0` is rejected, naming the key.
    #[test]
    fn limits_zero_max_reassembly_rejected() {
        let limits = LimitsConfig {
            max_reassembly: Some(0),
            ..Default::default()
        };
        let err = limits.validate().unwrap_err();
        assert!(err.to_string().contains("max_reassembly"));
    }

    /// `max_header_line` below the 256-byte floor is rejected.
    #[test]
    fn limits_small_max_header_line_rejected() {
        let limits = LimitsConfig {
            max_header_line: Some(255),
            ..Default::default()
        };
        let err = limits.validate().unwrap_err();
        assert!(err.to_string().contains("max_header_line"));
    }

    /// `max_header_line = 256` (the boundary) is accepted.
    #[test]
    fn limits_min_max_header_line_accepted() {
        let limits = LimitsConfig {
            max_header_line: Some(256),
            ..Default::default()
        };
        assert!(limits.validate().is_ok());
    }

    /// `max_headers_per_message = 0` is rejected, naming the key.
    #[test]
    fn limits_zero_max_headers_per_message_rejected() {
        let limits = LimitsConfig {
            max_headers_per_message: Some(0),
            ..Default::default()
        };
        let err = limits.validate().unwrap_err();
        assert!(err.to_string().contains("max_headers_per_message"));
    }

    /// `max_messages_per_dialog = 0` is rejected, naming the key.
    #[test]
    fn limits_zero_max_messages_per_dialog_rejected() {
        let limits = LimitsConfig {
            max_messages_per_dialog: Some(0),
            ..Default::default()
        };
        let err = limits.validate().unwrap_err();
        assert!(err.to_string().contains("max_messages_per_dialog"));
    }

    /// `max_audio_frames = 0` is rejected, naming the key.
    #[test]
    fn limits_zero_max_audio_frames_rejected() {
        let limits = LimitsConfig {
            max_audio_frames: Some(0),
            ..Default::default()
        };
        let err = limits.validate().unwrap_err();
        assert!(err.to_string().contains("max_audio_frames"));
    }
}
