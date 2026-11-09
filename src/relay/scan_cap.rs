// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! How many held calls one relay ask may cover: the one rule every surface
//! applies.
//!
//! A sessions scan sends one `list` and then one `query` per held call it
//! covers, so this number is what one ask costs the relay. A holdings ask
//! sends one `list` for up to this many Call-IDs. Before this module the CLI
//! read `--relay-holdings-max`, the TUI and REST used a fixed 32, and MCP took
//! the agent's `max_calls` with no upper bound. [`scan_cap`] is now the one
//! place the number is decided, for `--relay-holdings`, `--relay-sessions`,
//! the TUI sessions view, `GET /v1/relay/holdings`, `GET /v1/relay/sessions`
//! and the MCP `query_relay` tool.
//!
//! The rule:
//!
//! - a caller's own request (REST or MCP `max_calls`) applies when given;
//! - otherwise the operator's default applies: `--relay-holdings-max`, or
//!   [`SCAN_CAP_DEFAULT`] when the flag is not given;
//! - either is lowered to [`SCAN_CAP_CEILING`] when above it, and the answer
//!   says so with a [`CapClamp`]; it is never refused for being too large;
//! - 0 is refused ([`ZeroCap`]): an ask for no calls is a mistake, not a
//!   request the relay can answer.

use serde::Serialize;

/// The cap when neither the caller nor the operator names one.
///
/// rtpengine's own `list` default, and the value every surface used before
/// [`scan_cap`] existed.
pub const SCAN_CAP_DEFAULT: u32 = crate::relay::reconcile::DEFAULT_LIST_LIMIT;

/// The most held calls any one ask covers, on every surface.
///
/// [`crate::relay::reconcile::WIDE_LIST_LIMIT`]: the largest `list` sipnab
/// asks for anywhere, measured to fit the stream transport's reply.
pub const SCAN_CAP_CEILING: u32 = crate::relay::reconcile::WIDE_LIST_LIMIT;

/// A cap that was asked for above the ceiling of 1024 and lowered to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct CapClamp {
    /// The number of calls asked for.
    pub requested: u32,
    /// The ceiling it was lowered to; the ask covered at most this many.
    pub ceiling: u32,
}

impl CapClamp {
    /// The clamp as one sentence, for the text answers.
    #[must_use]
    pub fn sentence(&self) -> String {
        format!(
            "Asked for {} calls; the ceiling is {}, so at most {} were asked for.",
            self.requested, self.ceiling, self.ceiling
        )
    }
}

/// The cap one ask applies, and whether it was lowered to the ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanCap {
    /// The most held calls this ask covers.
    pub cap: u32,
    /// Set when the number asked for was above [`SCAN_CAP_CEILING`].
    pub clamped: Option<CapClamp>,
}

/// A cap of 0 was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroCap;

impl std::fmt::Display for ZeroCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the number of calls must be at least 1 (at most {SCAN_CAP_CEILING}; \
             a larger number is lowered to {SCAN_CAP_CEILING})"
        )
    }
}

impl std::error::Error for ZeroCap {}

/// The cap an ask applies: `requested` when given, else `configured`, else
/// [`SCAN_CAP_DEFAULT`], lowered to [`SCAN_CAP_CEILING`] when above it.
///
/// # Arguments
///
/// * `requested` — the caller's own number: REST or MCP `max_calls`.
/// * `configured` — the operator's default: `--relay-holdings-max`.
///
/// # Errors
///
/// [`ZeroCap`] when the number that applies is 0.
pub fn scan_cap(requested: Option<u32>, configured: Option<u32>) -> Result<ScanCap, ZeroCap> {
    let asked = requested.or(configured).unwrap_or(SCAN_CAP_DEFAULT);
    if asked == 0 {
        return Err(ZeroCap);
    }
    Ok(if asked > SCAN_CAP_CEILING {
        ScanCap {
            cap: SCAN_CAP_CEILING,
            clamped: Some(CapClamp {
                requested: asked,
                ceiling: SCAN_CAP_CEILING,
            }),
        }
    } else {
        ScanCap {
            cap: asked,
            clamped: None,
        }
    })
}

/// Parse `--relay-holdings-max`: a whole number, refused when [`scan_cap`]
/// refuses it.
///
/// # Errors
///
/// A message naming the problem when the text is not a whole number or is 0.
pub fn parse_cap_flag(text: &str) -> Result<u32, String> {
    let n: u32 = text
        .parse()
        .map_err(|e| format!("{text:?} is not a whole number of calls: {e}"))?;
    scan_cap(None, Some(n)).map_err(|e| e.to_string())?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// Nothing named: the default, unclamped.
    #[test]
    fn nothing_named_takes_the_default() -> Result<(), TestError> {
        let c = scan_cap(None, None)?;
        assert_eq!(c.cap, 32, "Nothing named: the default, unclamped");
        assert_eq!(c.clamped, None, "Nothing named: the default, unclamped");
        Ok(())
    }

    /// The operator's flag sets the default when the caller names none.
    #[test]
    fn the_flag_sets_the_default() -> Result<(), TestError> {
        assert_eq!(
            scan_cap(None, Some(100))?.cap,
            100,
            "The operator's flag sets the default when the caller names none"
        );
        Ok(())
    }

    /// A caller's own number applies over the operator's default, below it
    /// and above it.
    #[test]
    fn a_request_applies_over_the_flag() -> Result<(), TestError> {
        assert_eq!(scan_cap(Some(5), Some(100))?.cap, 5, "below the flag");
        assert_eq!(scan_cap(Some(500), Some(100))?.cap, 500, "above the flag");
        Ok(())
    }

    /// A request above the ceiling is lowered to it and says so.
    #[test]
    fn a_request_above_the_ceiling_is_clamped_and_says_so() -> Result<(), TestError> {
        let c = scan_cap(Some(100_000), None)?;
        assert_eq!(
            c.cap, 1024,
            "A request above the ceiling is lowered to it and says so"
        );
        assert_eq!(
            c.clamped,
            Some(CapClamp {
                requested: 100_000,
                ceiling: 1024
            }),
            "A request above the ceiling is lowered to it and says so"
        );
        Ok(())
    }

    /// `u32::MAX` is clamped like any other large number.
    #[test]
    fn the_largest_request_is_clamped() -> Result<(), TestError> {
        let c = scan_cap(Some(u32::MAX), Some(7))?;
        assert_eq!(
            c.cap, SCAN_CAP_CEILING,
            "`u32::MAX` is clamped like any other large number"
        );
        assert_eq!(
            c.clamped.map(|k| k.requested),
            Some(u32::MAX),
            "`u32::MAX` is clamped like any other large number"
        );
        Ok(())
    }

    /// A flag above the ceiling is lowered the same way.
    #[test]
    fn a_flag_above_the_ceiling_is_clamped() -> Result<(), TestError> {
        let c = scan_cap(None, Some(5000))?;
        assert_eq!(
            c.cap, 1024,
            "A flag above the ceiling is lowered the same way"
        );
        assert_eq!(
            c.clamped.map(|k| k.requested),
            Some(5000),
            "A flag above the ceiling is lowered the same way"
        );
        Ok(())
    }

    /// Exactly the ceiling is not a clamp; one above it is.
    #[test]
    fn the_ceiling_itself_is_not_clamped() -> Result<(), TestError> {
        assert_eq!(
            scan_cap(Some(1024), None)?.clamped,
            None,
            "Exactly the ceiling is not a clamp; one above it is"
        );
        assert_eq!(
            scan_cap(Some(1024), None)?.cap,
            1024,
            "Exactly the ceiling is not a clamp; one above it is"
        );
        assert!(
            scan_cap(Some(1025), None)?.clamped.is_some(),
            "Exactly the ceiling is not a clamp; one above it is"
        );
        Ok(())
    }

    /// One call is the smallest ask, and is not clamped.
    #[test]
    fn one_call_is_the_smallest_ask() -> Result<(), TestError> {
        let c = scan_cap(Some(1), None)?;
        assert_eq!(
            (c.cap, c.clamped),
            (1, None),
            "One call is the smallest ask, and is not clamped"
        );
        Ok(())
    }

    /// A request of 0 is refused, whatever the flag says.
    #[test]
    fn a_request_of_zero_is_refused() {
        assert_eq!(
            scan_cap(Some(0), None),
            Err(ZeroCap),
            "A request of 0 is refused, whatever the flag says"
        );
        assert_eq!(
            scan_cap(Some(0), Some(50)),
            Err(ZeroCap),
            "A request of 0 is refused, whatever the flag says"
        );
    }

    /// A default of 0 is refused too, so no path asks for no calls.
    #[test]
    fn a_default_of_zero_is_refused() {
        assert_eq!(
            scan_cap(None, Some(0)),
            Err(ZeroCap),
            "A default of 0 is refused too, so no path asks for no calls"
        );
    }

    /// The refusal names the bounds, so the caller knows what to send.
    #[test]
    fn the_refusal_names_the_bounds() {
        let text = ZeroCap.to_string();
        assert!(text.contains("at least 1"), "{text}");
        assert!(text.contains("1024"), "{text}");
    }

    /// The constants are the relay limits they name.
    #[test]
    fn the_bounds_are_the_relay_limits() {
        assert_eq!(
            SCAN_CAP_DEFAULT, 32,
            "The constants are the relay limits they name"
        );
        assert_eq!(
            SCAN_CAP_CEILING, 1024,
            "The constants are the relay limits they name"
        );
    }

    /// The clamp's sentence names both numbers.
    #[test]
    fn the_clamp_sentence_names_both_numbers() {
        let s = CapClamp {
            requested: 5000,
            ceiling: 1024,
        }
        .sentence();
        assert!(s.contains("5000") && s.contains("1024"), "{s}");
    }

    /// The clamp's wire form is the two numbers.
    #[test]
    fn the_clamp_serializes_both_numbers() -> Result<(), TestError> {
        let v = serde_json::to_value(CapClamp {
            requested: 5000,
            ceiling: 1024,
        })?;
        assert_eq!(
            v,
            serde_json::json!({ "requested": 5000, "ceiling": 1024 }),
            "The clamp's wire form is the two numbers"
        );
        Ok(())
    }

    /// The flag parser takes a whole number and leaves a large one for the
    /// clamp.
    #[test]
    fn the_flag_parser_keeps_a_large_number_for_the_clamp() -> Result<(), TestError> {
        assert_eq!(
            parse_cap_flag("7")?,
            7,
            "The flag parser takes a whole number and leaves a large one for the clamp"
        );
        assert_eq!(
            parse_cap_flag("5000")?,
            5000,
            "The flag parser takes a whole number and leaves a large one for the clamp"
        );
        Ok(())
    }

    /// The flag parser refuses 0 with the rule's own words.
    #[test]
    fn the_flag_parser_refuses_zero() {
        assert_eq!(
            parse_cap_flag("0"),
            Err(ZeroCap.to_string()),
            "The flag parser refuses 0 with the rule's own words"
        );
    }

    /// The flag parser refuses text that is not a whole number.
    #[test]
    fn the_flag_parser_refuses_text() {
        for bad in ["", "-1", "ten", "4294967296"] {
            assert!(parse_cap_flag(bad).is_err(), "{bad:?}");
        }
    }
}
