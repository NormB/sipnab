//! Configuration file loading for sipnab.
//!
//! Supports TOML configuration with cascading file search:
//! explicit path > `$SIPNAB_CONFIG` > `~/.config/sipnab/sipnab.toml` >
//! `~/.sipnabrc` > `/etc/sipnab/sipnab.toml`.
//!
//! Unknown keys produce a warning (not a hard error) to allow forward
//! compatibility when configs are shared across versions.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level configuration, deserialized from TOML.
///
/// All sections are optional and use defaults when omitted. Unknown fields
/// trigger a warning on first parse attempt and are silently ignored on the
/// lenient re-parse.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StrictConfig {
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

/// Top-level configuration (lenient — ignores unknown fields).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct DisplayConfig {
    /// Color mode ("auto", "always", "never").
    pub color: Option<String>,
    /// Maximum payload bytes to display.
    pub payload_limit: Option<usize>,
    /// Show delta time by default.
    pub delta_time: Option<bool>,
}

/// Filter presets.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
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
}

/// Privilege settings.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct PrivilegeConfig {
    /// User to drop privileges to.
    pub user: Option<String>,
    /// Disable privilege dropping.
    pub no_priv_drop: Option<bool>,
    /// Chroot directory.
    pub chroot: Option<String>,
}

/// TUI theme configuration.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct ThemeConfig {
    /// Background color.
    pub background: Option<String>,
    /// Foreground color.
    pub foreground: Option<String>,
    /// Highlight color.
    pub highlight: Option<String>,
}

/// TUI keybinding overrides.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct KeybindingsConfig {
    /// Key to quit.
    pub quit: Option<String>,
    /// Key to show help.
    pub help: Option<String>,
    /// Key to toggle filter.
    pub filter: Option<String>,
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
    /// First attempts a strict parse (unknown fields rejected). If that fails
    /// due to unknown fields, logs a warning and falls back to lenient parsing.
    fn load_file(path: &Path) -> Result<Config, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        // Try strict parse first
        match toml::from_str::<StrictConfig>(&content) {
            Ok(strict) => Ok(Config {
                capture: strict.capture,
                display: strict.display,
                filter: strict.filter,
                security: strict.security,
                limits: strict.limits,
                privilege: strict.privilege,
                theme: strict.theme,
                keybindings: strict.keybindings,
            }),
            Err(strict_err) => {
                let err_msg = strict_err.to_string();
                if err_msg.contains("unknown field") {
                    log::warn!(
                        "Config file {} contains unknown keys ({}); ignoring them",
                        path.display(),
                        err_msg
                    );
                    // Lenient re-parse
                    toml::from_str::<Config>(&content)
                        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))
                } else {
                    Err(format!(
                        "Failed to parse {}: {}",
                        path.display(),
                        strict_err
                    ))
                }
            }
        }
    }

    /// Dump the effective configuration to stdout.
    ///
    /// Used by `--dump-config` to show what sipnab would use.
    pub fn dump(&self) {
        println!("# sipnab effective configuration");
        println!();
        println!("[capture]");
        if let Some(ref d) = self.capture.device {
            println!("device = \"{}\"", d);
        }
        if let Some(ref pr) = self.capture.portrange {
            println!("portrange = \"{}\"", pr);
        }
        if let Some(sl) = self.capture.snaplen {
            println!("snaplen = {}", sl);
        }
        if let Some(buf) = self.capture.buffer {
            println!("buffer = {}", buf);
        }
        if let Some(nr) = self.capture.no_rtp {
            println!("no_rtp = {}", nr);
        }
        println!();
        println!("[display]");
        if let Some(ref c) = self.display.color {
            println!("color = \"{}\"", c);
        }
        if let Some(pl) = self.display.payload_limit {
            println!("payload_limit = {}", pl);
        }
        if let Some(dt) = self.display.delta_time {
            println!("delta_time = {}", dt);
        }
        println!();
        println!("[filter]");
        if let Some(ref f) = self.filter.from {
            println!("from = \"{}\"", f);
        }
        if let Some(ref t) = self.filter.to {
            println!("to = \"{}\"", t);
        }
        if let Some(ref e) = self.filter.expression {
            println!("expression = \"{}\"", e);
        }
        println!();
        println!("[security]");
        if let Some(ks) = self.security.kill_scanner {
            println!("kill_scanner = {}", ks);
        }
        if let Some(kr) = self.security.kill_response {
            println!("kill_response = {}", kr);
        }
        if let Some(fd) = self.security.fraud_detect {
            println!("fraud_detect = {}", fd);
        }
        if let Some(ref a) = self.security.alert {
            println!("alert = {:?}", a);
        }
        if let Some(ref ae) = self.security.alert_exec {
            println!("alert_exec = \"{}\"", ae);
        }
        println!();
        println!("[limits]");
        if let Some(dl) = self.limits.dialog_limit {
            println!("dialog_limit = {}", dl);
        }
        if let Some(ms) = self.limits.max_streams {
            println!("max_streams = {}", ms);
        }
        if let Some(mr) = self.limits.max_reassembly {
            println!("max_reassembly = {}", mr);
        }
        if let Some(hr) = self.limits.hep_rate_limit {
            println!("hep_rate_limit = {}", hr);
        }
        println!();
        println!("[privilege]");
        if let Some(ref u) = self.privilege.user {
            println!("user = \"{}\"", u);
        }
        if let Some(np) = self.privilege.no_priv_drop {
            println!("no_priv_drop = {}", np);
        }
        if let Some(ref c) = self.privilege.chroot {
            println!("chroot = \"{}\"", c);
        }
        println!();
        println!("[theme]");
        if let Some(ref bg) = self.theme.background {
            println!("background = \"{}\"", bg);
        }
        if let Some(ref fg) = self.theme.foreground {
            println!("foreground = \"{}\"", fg);
        }
        if let Some(ref hl) = self.theme.highlight {
            println!("highlight = \"{}\"", hl);
        }
        println!();
        println!("[keybindings]");
        if let Some(ref q) = self.keybindings.quit {
            println!("quit = \"{}\"", q);
        }
        if let Some(ref h) = self.keybindings.help {
            println!("help = \"{}\"", h);
        }
        if let Some(ref f) = self.keybindings.filter {
            println!("filter = \"{}\"", f);
        }
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
        assert_eq!(config.keybindings.quit.as_deref(), Some("q"));
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "[capture]\ndevice = \"lo\"\nnonexistent_key = true").unwrap();

        // Should succeed with lenient parse (unknown key in section)
        let loaded = Config::load(Some(path.to_str().unwrap()), false).unwrap();
        assert_eq!(loaded.config.capture.device.as_deref(), Some("lo"));
    }

    #[test]
    fn env_var_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "[display]\ncolor = \"never\"").unwrap();

        // Temporarily set env var (unsafe in Rust 2024 edition)
        // SAFETY: This test runs single-threaded and restores the var immediately.
        unsafe {
            std::env::set_var("SIPNAB_CONFIG", path.to_str().unwrap());
        }
        let loaded = Config::load(None, false).unwrap();
        unsafe {
            std::env::remove_var("SIPNAB_CONFIG");
        }

        assert_eq!(loaded.config.display.color.as_deref(), Some("never"));
    }
}
