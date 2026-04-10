//! Security analysis and detection for SIP traffic.
//!
//! This module provides real-time detection of SIP security threats including
//! scanner reconnaissance, toll fraud patterns, digest authentication
//! vulnerabilities, registration floods, and a rule-based alerting engine.

pub mod alerting;
pub mod digest_leak;
pub mod fraud_detect;
pub mod reg_flood;
pub mod scanner_detect;
pub mod scanner_kill;

pub use alerting::{AlertEngine, AlertRule};
pub use digest_leak::{DigestAlert, DigestLeakDetector, DigestVulnerability};
pub use fraud_detect::{FraudAlert, FraudDetector, FraudType};
pub use reg_flood::{RegFloodAlert, RegFloodDetector};
pub use scanner_detect::{ScannerAlert, ScannerDetector};
