//! Configuration file loading for sipnab.
//!
//! Supports TOML configuration with cascading file search:
//! explicit path > `$SIPNAB_CONFIG` > `~/.config/sipnab/sipnab.toml` >
//! `~/.sipnabrc` > `/etc/sipnab/sipnab.toml`.
//!
//! Unknown keys produce a warning (not a hard error) to allow forward
//! compatibility when configs are shared across versions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Known valid keys per config section.
fn known_keys() -> HashMap<&'static str, &'static [&'static str]> {
    let mut m = HashMap::new();
    m.insert(
        "",
        [
            "capture",
            "display",
            "filter",
            "security",
            "limits",
            "privilege",
            "theme",
            "keybindings",
        ]
        .as_slice(),
    );
    m.insert(
        "capture",
        ["device", "portrange", "snaplen", "buffer", "no_rtp"].as_slice(),
    );
    m.insert(
        "display",
        ["color", "payload_limit", "delta_time", "visible_columns"].as_slice(),
    );
    m.insert("filter", ["from", "to", "expression"].as_slice());
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
        ]
        .as_slice(),
    );
    m.insert("privilege", ["user", "no_priv_drop", "chroot"].as_slice());
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
}

/// Walk a parsed TOML value and warn about any keys not in the known set.
fn warn_unknown_keys(value: &toml::Value) {
    let known = known_keys();

    let table = match value.as_table() {
        Some(t) => t,
        None => return,
    };

    let Some(root_keys) = known.get("") else { return };
    for key in table.keys() {
        if !root_keys.contains(&key.as_str()) {
            log::warn!("Unknown config key: {key}");
        }
    }

    for (section, val) in table {
        if let Some(section_table) = val.as_table()
            && let Some(valid_keys) = known.get(section.as_str())
        {
            for key in section_table.keys() {
                if !valid_keys.contains(&key.as_str()) {
                    log::warn!("Unknown config key: {section}.{key}");
                }
            }
        }
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
    /// Security detection settings.
    #[serde(default)]
    pub security: SecurityConfig,
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
}

/// Packet capture configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CaptureConfig {
    /// Default network interface.
    pub device: Option<String>,
    /// SIP port range.
    pub portrange: Option<String>,
    /// Snapshot length.
    pub snaplen: Option<u32>,
    /// Kernel buffer size (MiB).
    pub buffer: Option<u32>,
    /// Disable RTP capture by default.
    pub no_rtp: Option<bool>,
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
    /// `"Destination"`, `"State"`, `"Msgs"`, `"Date"`, `"PDD"`.
    /// When set, only the listed columns are shown; unlisted columns are hidden.
    /// When unset, all columns are visible (the default).
    pub visible_columns: Option<Vec<String>>,
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

/// Resource limits.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum tracked dialogs.
    pub dialog_limit: Option<u64>,
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
            log::warn!("Unknown color value: {s:?}");
            None
        }
    }
}

/// Parse a key name into a crossterm KeyCode.
///
/// Accepts: single characters (`"q"`, `"/"`), function keys (`"F1"`–`"F12"`),
/// or special names (`"Esc"`, `"Space"`, `"Enter"`, `"Tab"`).
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
        _ if s.starts_with('F') || s.starts_with('f') => {
            s[1..].parse::<u8>().ok().filter(|&n| (1..=12).contains(&n)).map(KeyCode::F)
        }
        _ => {
            log::warn!("Unknown keybinding value: {s:?}");
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
    pub fn load(explicit_path: Option<&str>, skip_default: bool) -> Result<LoadedConfig, String> {
        if skip_default {
            log::debug!("Config loading skipped (--no-config)");
            return Ok(LoadedConfig {
                config: Config::default(),
                source: None,
            });
        }

        // 1. Explicit path — must exist
        if let Some(path) = explicit_path {
            let p = PathBuf::from(path);
            if !p.exists() {
                return Err(format!("Config file not found: {}", p.display()));
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
            log::debug!(
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

        log::debug!("No config file found, using defaults");
        Ok(LoadedConfig {
            config: Config::default(),
            source: None,
        })
    }

    /// Load and parse a single config file.
    ///
    /// Parses TOML into a generic `toml::Value` first, walks the keys against
    /// the known valid set (warning on unknowns), then deserializes leniently
    /// into `Config`.
    fn load_file(path: &Path) -> Result<Config, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        Self::parse_toml(&content, Some(path))
    }

    /// Parse TOML content, warn about unknown keys, and deserialize leniently.
    ///
    /// Separated from `load_file` so unit tests can call it without a real file.
    fn parse_toml(content: &str, path: Option<&Path>) -> Result<Config, String> {
        let display = path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<inline>".to_string());

        // Parse into generic TOML value to walk keys
        let value: toml::Value = content
            .parse()
            .map_err(|e| format!("Failed to parse {display}: {e}"))?;

        warn_unknown_keys(&value);

        // Deserialize leniently into Config
        toml::from_str::<Config>(content).map_err(|e| format!("Failed to parse {display}: {e}"))
    }

    /// Dump the effective configuration as TOML.
    ///
    /// Used by `--dump-config` to show what sipnab would use.
    pub fn dump(&self) -> String {
        toml::to_string_pretty(self)
            .unwrap_or_else(|e| format!("# Failed to serialize config: {e}"))
    }
}

/// Return the default config file search paths (items 3-5).
fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = home_dir() {
        paths.push(home.join(".config").join("sipnab").join("sipnab.toml"));
        paths.push(home.join(".sipnabrc"));
    }

    paths.push(PathBuf::from("/etc/sipnab/sipnab.toml"));
    paths
}

/// Get the user's home directory.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config_is_valid() {
        let config = Config::default();
        assert!(config.capture.device.is_none());
        assert!(config.display.color.is_none());
        assert!(config.security.kill_scanner.is_none());
    }

    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
[capture]
device = "eth0"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.capture.device.as_deref(), Some("eth0"));
        assert!(config.display.color.is_none());
    }

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

    #[test]
    fn skip_default_returns_empty() {
        let loaded = Config::load(None, true).unwrap();
        assert!(loaded.source.is_none());
        assert_eq!(loaded.config, Config::default());
    }

    #[test]
    fn missing_explicit_file_errors() {
        let result = Config::load(Some("/nonexistent/sipnab.toml"), false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

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

    #[test]
    fn visible_columns_absent_is_none() {
        let toml_str = "[display]\ncolor = \"auto\"\n";
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.display.visible_columns.is_none());
    }

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
}
