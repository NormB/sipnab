// SPDX-License-Identifier: MIT OR Apache-2.0

//! VoIP security detection: SIP scanner detection, toll fraud, registration
//! flooding, digest credential leaks, and alerting.
//!
//! This module provides real-time detection of SIP security threats including
//! scanner reconnaissance, toll fraud patterns, digest authentication
//! vulnerabilities, registration floods, and a rule-based alerting engine.

pub mod alerting;
pub mod digest_leak;
pub mod fraud_detect;
pub mod kill_packet;
pub mod reg_flood;
pub mod scanner_detect;
pub mod scanner_kill;
// Names `capture::CaptureSource`, which exists only in native builds; gated to
// match `crate::process_isolation`, the module whose sends it guards.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod transmit_guard;

pub use alerting::{AlertEngine, AlertRule};
pub use digest_leak::{DigestAlert, DigestLeakDetector, DigestVulnerability};
pub use fraud_detect::{FraudAlert, FraudDetector, FraudType};
pub use reg_flood::{RegFloodAlert, RegFloodDetector};
pub use scanner_detect::{ScannerAlert, ScannerDetector};
