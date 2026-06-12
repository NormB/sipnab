//! Structured library errors.
//!
//! The library surface used to return `Result<_, String>` in several
//! places, which forced callers to pattern-match on message text. These
//! variants are matchable; `Display` carries the actionable message.

/// Errors returned by sipnab's library surface (config loading,
/// validation, and address/rule parsing).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An explicitly requested config file does not exist.
    #[error("config file not found: {path}")]
    ConfigNotFound {
        /// The path that was requested.
        path: String,
    },

    /// A config file exists but could not be read.
    #[error("cannot read config file {path}: {reason}")]
    ConfigRead {
        /// The file that failed to read.
        path: String,
        /// The underlying I/O error text.
        reason: String,
    },

    /// A config file is not valid TOML (or has invalid key types).
    #[error("invalid config {path}: {reason}")]
    ConfigParse {
        /// The file that failed to parse ("<inline>" for string input).
        path: String,
        /// The TOML error text.
        reason: String,
    },

    /// Config values parsed but failed semantic validation.
    #[error("invalid config value: {0}")]
    ConfigInvalid(String),

    /// Config serialization (`--dump-config`) failed.
    #[error("cannot serialize config: {0}")]
    ConfigSerialize(String),

    /// A CIDR range (HEP allowlist) could not be parsed.
    #[error("invalid CIDR '{input}': {reason}")]
    InvalidCidr {
        /// The offending input.
        input: String,
        /// Why it failed.
        reason: String,
    },

    /// A bind address (API / metrics / MCP HTTP) could not be parsed.
    #[error("invalid bind address '{input}': {reason}")]
    InvalidBindAddr {
        /// The offending input.
        input: String,
        /// Why it failed.
        reason: String,
    },

    /// An alert rule (`--alert`) could not be parsed.
    #[error("invalid alert rule '{input}': {reason}")]
    InvalidAlertRule {
        /// The offending input.
        input: String,
        /// Why it failed.
        reason: String,
    },

    /// CLI flag combination failed validation.
    #[error("{0}")]
    CliValidation(String),

    /// A server (API / metrics) failed to start or run.
    #[error("server error: {0}")]
    Server(String),
}
