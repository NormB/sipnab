//! sipnab — SIP & RTP capture, analysis, and security library.
//!
//! This crate provides the core components for SIP/RTP packet capture,
//! analysis, and security monitoring. The binary entry point is in `main.rs`.

pub mod capture;
pub mod cli;
pub mod config;
pub mod output;
pub mod rtp;
pub mod security;
pub mod signals;
pub mod sip;

#[cfg(feature = "tui")]
pub mod tui;
