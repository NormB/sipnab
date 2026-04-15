//! sipnab — SIP & RTP capture, analysis, and security library.
//!
//! Provides zero-copy SIP parsing, RTP quality metrics (MOS, jitter, loss),
//! dialog state tracking, a filter DSL for matching calls, and security
//! detection (scanners, fraud, digest leaks). Used by the sipnab CLI/TUI
//! tool and available as a library for custom VoIP analysis applications.
//!
//! # Quick Start
//!
//! ```no_run
//! use sipnab::PcapReader;
//! use sipnab::sip::parser::parse_sip;
//! use sipnab::capture::parse::parse_packet;
//!
//! let data = std::fs::read("capture.pcap").unwrap();
//! let reader = PcapReader::new(&data).unwrap();
//! for pkt in reader {
//!     // Process packets...
//! }
//! ```

pub mod capture;
#[doc(hidden)]
#[cfg(feature = "native")]
pub mod cli;
pub mod config;
pub mod crypto;
#[cfg(feature = "native")]
pub mod output;
#[doc(hidden)]
#[cfg(not(target_arch = "wasm32"))]
pub mod privilege;
#[doc(hidden)]
#[cfg(not(target_arch = "wasm32"))]
pub mod process_isolation;
pub mod rtp;
pub mod security;
#[doc(hidden)]
#[cfg(not(target_arch = "wasm32"))]
pub mod signals;
pub mod sip;

#[doc(hidden)]
#[cfg(feature = "tui")]
pub mod tui;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(test)]
pub mod test_utils;

// Convenience re-exports for library consumers
pub use capture::pcap_reader::PcapReader;
pub use rtp::quality::estimate_mos;
pub use rtp::stream::{RtpStream, StreamKey};
pub use rtp::stream_store::StreamStore;
pub use sip::SipMethod;
pub use sip::dialog::{DialogState, SipDialog};
pub use sip::dialog_store::DialogStore;
pub use sip::dsl::FilterExpr;
pub use sip::message::SipMessage;
