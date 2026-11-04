// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A duration as an operator types it: `30s`, `5m`, `2h`.
//!
//! One parser for every flag that takes one. `--duration` and the
//! `--alert-rule` window and cooldown had a parser each, with their own
//! overflow guards and their own idea of what to quote when refusing. They
//! differ in one rule only, whether a number with no unit is accepted, and
//! that is a parameter here.

use std::time::Duration;

/// What a number with no unit means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareNumber {
    /// A number with no unit is seconds: `--duration 30` is 30 seconds.
    Seconds,
    /// A number with no unit is refused: an `--alert-rule` window must say
    /// its unit.
    Refused,
}

/// Parse `typed` as a duration with an `s`, `m` or `h` unit.
///
/// Surrounding whitespace is ignored. A refusal quotes `typed` exactly as
/// given, never the text left once a unit was taken off.
///
/// # Errors
///
/// When `typed` is empty, is not a whole number of a known unit, has no unit
/// and `bare` is [`BareNumber::Refused`], or is too large for `u64` seconds.
pub fn parse(typed: &str, bare: BareNumber) -> anyhow::Result<Duration> {
    use anyhow::{Context as _, bail};

    let s = typed.trim();
    if s.is_empty() {
        bail!("Empty duration string");
    }
    let (number, multiplier) = if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else if s.ends_with(|c: char| c.is_ascii_digit()) && bare == BareNumber::Refused {
        bail!("Duration has no unit (s, m or h): '{typed}'");
    } else {
        (s, 1u64)
    };
    let value: u64 = number
        .parse()
        .with_context(|| format!("Invalid duration value: '{typed}'"))?;
    // `value * multiplier` panicked in debug and wrapped in release on a value
    // large enough to overflow `u64` seconds (e.g. `18446744073709551615m`).
    let secs = value
        .checked_mul(multiplier)
        .with_context(|| format!("Duration too large: '{typed}'"))?;
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// Both policies, for the cases where the rule does not depend on one.
    const BOTH: [BareNumber; 2] = [BareNumber::Seconds, BareNumber::Refused];

    /// The refusal text for `typed`, or `None` when it parses.
    fn refusal(typed: &str, bare: BareNumber) -> Option<String> {
        parse(typed, bare).err().map(|e| e.to_string())
    }

    /// Each unit, under either policy.
    #[test]
    fn each_unit_parses() -> Result<(), TestError> {
        for bare in BOTH {
            assert_eq!(parse("30s", bare)?, Duration::from_secs(30), "{bare:?}");
            assert_eq!(parse("5m", bare)?, Duration::from_secs(300), "{bare:?}");
            assert_eq!(parse("2h", bare)?, Duration::from_secs(7200), "{bare:?}");
            assert_eq!(parse(" 5m ", bare)?, Duration::from_secs(300), "{bare:?}");
        }
        Ok(())
    }

    /// A number with no unit is seconds, or refused, as the caller says.
    #[test]
    fn a_bare_number_follows_the_policy() -> Result<(), TestError> {
        assert_eq!(
            parse("30", BareNumber::Seconds)?,
            Duration::from_secs(30),
            "a bare number is seconds"
        );
        assert_eq!(
            refusal("30", BareNumber::Refused).as_deref(),
            Some("Duration has no unit (s, m or h): '30'"),
            "a bare number is refused, quoted as typed"
        );
        Ok(())
    }

    /// Empty text, text that is not a number, and an unknown unit are
    /// refused under either policy.
    #[test]
    fn malformed_text_is_refused() {
        for bare in BOTH {
            assert_eq!(
                refusal("", bare).as_deref(),
                Some("Empty duration string"),
                "{bare:?}"
            );
            for typed in ["abc", "5x", "5 m", "-5s"] {
                assert!(refusal(typed, bare).is_some(), "{typed:?} under {bare:?}");
            }
        }
    }

    /// A refusal quotes the value exactly as the operator gave it, never the
    /// text left once a unit suffix was taken off.
    #[test]
    fn a_refusal_quotes_the_value_as_typed() {
        for bare in BOTH {
            assert_eq!(
                refusal("five-minutes", bare).as_deref(),
                Some("Invalid duration value: 'five-minutes'"),
                "{bare:?}"
            );
            assert_eq!(
                refusal("m", bare).as_deref(),
                Some("Invalid duration value: 'm'"),
                "a unit with no number, under {bare:?}"
            );
            assert_eq!(
                refusal("18446744073709551615m", bare).as_deref(),
                Some("Duration too large: '18446744073709551615m'"),
                "{bare:?}"
            );
        }
    }

    /// A multibyte final character is refused as an unknown unit, not a
    /// panic on a byte split inside it.
    #[test]
    fn a_multibyte_final_character_is_refused() {
        for bare in BOTH {
            for typed in ["10µ", "5秒", "µ"] {
                assert_eq!(
                    refusal(typed, bare),
                    Some(format!("Invalid duration value: '{typed}'")),
                    "{typed:?} under {bare:?}"
                );
            }
        }
    }

    /// A value that overflows `u64` seconds once its unit is applied is
    /// refused, not a panic or a wrapped value; the largest that fits parses.
    #[test]
    fn an_overflow_is_refused_and_the_largest_value_fits() -> Result<(), TestError> {
        for bare in BOTH {
            assert!(
                parse("18446744073709551615m", bare).is_err(),
                "u64::MAX minutes, {bare:?}"
            );
            assert!(
                parse("18446744073709551615h", bare).is_err(),
                "u64::MAX hours, {bare:?}"
            );
            assert_eq!(
                parse("5124095576030431h", bare)?,
                Duration::from_secs(18_446_744_073_709_551_600),
                "u64::MAX / 3600 hours fits, {bare:?}"
            );
            assert!(
                parse("5124095576030432h", bare).is_err(),
                "one hour more overflows, {bare:?}"
            );
            assert!(
                parse("18446744073709551616s", bare).is_err(),
                "more seconds than u64 holds, {bare:?}"
            );
        }
        Ok(())
    }
}
