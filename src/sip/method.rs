// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIP request method enum.
//!
//! Replaces stringly-typed method fields with a proper enum that covers
//! all standard RFC 3261 methods plus common extensions. Non-standard
//! methods are held in `Custom(Box<str>)`.

/// SIP request method.
///
/// Covers RFC 3261 core methods (INVITE, ACK, BYE, CANCEL, REGISTER,
/// OPTIONS) and common extensions (PRACK, SUBSCRIBE, NOTIFY, PUBLISH,
/// INFO, REFER, MESSAGE, UPDATE). Any other method is stored as
/// `Custom(Box<str>)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[non_exhaustive]
pub enum SipMethod {
    /// INVITE — initiate or modify a session.
    Invite,
    /// ACK — confirm a final INVITE response.
    Ack,
    /// BYE — terminate an established session.
    Bye,
    /// CANCEL — abort a pending INVITE.
    Cancel,
    /// REGISTER — bind a contact to an address-of-record.
    Register,
    /// OPTIONS — query capabilities.
    Options,
    /// PRACK — acknowledge a provisional response (RFC 3262).
    Prack,
    /// SUBSCRIBE — request event notification (RFC 6665).
    Subscribe,
    /// NOTIFY — deliver an event notification (RFC 6665).
    Notify,
    /// PUBLISH — publish event state (RFC 3903).
    Publish,
    /// INFO — mid-session information (RFC 6086).
    Info,
    /// REFER — request a call transfer (RFC 3515).
    Refer,
    /// MESSAGE — instant message (RFC 3428).
    Message,
    /// UPDATE — modify session state before answer (RFC 3311).
    Update,
    /// Non-standard method (e.g., proprietary extensions).
    Custom(Box<str>),
}

impl SipMethod {
    /// Return the canonical uppercase string representation.
    ///
    /// Takes `&self` (unlike [`TransportProto::as_str`](crate::net::TransportProto::as_str),
    /// which takes `self`) because `SipMethod` is not `Copy` — the
    /// `Custom(Box<str>)` variant owns its name and the returned `&str`
    /// borrows from it.
    ///
    /// # Examples
    ///
    /// ```
    /// use sipnab::SipMethod;
    ///
    /// assert_eq!(SipMethod::parse("INVITE").as_str(), "INVITE");
    /// // Unknown methods round-trip through Custom:
    /// assert_eq!(SipMethod::parse("PUBLISH").as_str(), "PUBLISH");
    /// ```
    pub fn as_str(&self) -> &str {
        match self {
            Self::Invite => "INVITE",
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Register => "REGISTER",
            Self::Options => "OPTIONS",
            Self::Prack => "PRACK",
            Self::Subscribe => "SUBSCRIBE",
            Self::Notify => "NOTIFY",
            Self::Publish => "PUBLISH",
            Self::Info => "INFO",
            Self::Refer => "REFER",
            Self::Message => "MESSAGE",
            Self::Update => "UPDATE",
            Self::Custom(s) => s,
        }
    }

    /// Parse a string into a `SipMethod`.
    ///
    /// # Arguments
    ///
    /// * `s` — method token exactly as it appears on the request line
    ///   (matching is case-sensitive, per RFC 3261 §7.1).
    ///
    /// # Returns
    ///
    /// The matching enum variant for a known method; anything else becomes
    /// `Custom` holding the original string. Never fails.
    pub fn parse(s: &str) -> Self {
        match s {
            "INVITE" => Self::Invite,
            "ACK" => Self::Ack,
            "BYE" => Self::Bye,
            "CANCEL" => Self::Cancel,
            "REGISTER" => Self::Register,
            "OPTIONS" => Self::Options,
            "PRACK" => Self::Prack,
            "SUBSCRIBE" => Self::Subscribe,
            "NOTIFY" => Self::Notify,
            "PUBLISH" => Self::Publish,
            "INFO" => Self::Info,
            "REFER" => Self::Refer,
            "MESSAGE" => Self::Message,
            "UPDATE" => Self::Update,
            other => Self::Custom(other.into()),
        }
    }
}

impl std::fmt::Display for SipMethod {
    /// Write the canonical uppercase method name (same as `as_str`) to `f`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for SipMethod {
    /// Compare the canonical string form against `other` (case-sensitive).
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialOrd for SipMethod {
    /// Delegate to `Ord::cmp`; always returns `Some` (total order).
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SipMethod {
    /// Order methods lexicographically by their canonical string form.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

/// Tests for `SipMethod` parsing, display, equality, and ordering.
#[cfg(test)]
mod tests {
    /// The enum covers the IANA SIP methods registry exactly — no gaps, no
    /// inventions.
    ///
    /// The registry is the list of record
    /// (<https://www.iana.org/assignments/sip-parameters/sip-parameters-6.csv>,
    /// retrieved 2026-07-30). RFC 3261 defines six of these and later RFCs
    /// register the rest, so no single RFC carries the whole set — the same
    /// arrangement as the response codes in `docs/sip-response-codes.md`.
    ///
    /// This matters for the dialog state machine, which dispatches on the
    /// method: a method the enum does not name becomes `Custom` and falls to
    /// the generic handler, which is right for a private extension and wrong
    /// for a registered one nobody noticed. Pinning the set means a new
    /// registration is a decision rather than a silent default.
    #[test]
    fn covers_the_iana_methods_registry() {
        // sip-parameters-6.csv, "Methods" column, verbatim.
        const REGISTRY: [&str; 14] = [
            "ACK",
            "BYE",
            "CANCEL",
            "INFO",
            "INVITE",
            "MESSAGE",
            "NOTIFY",
            "OPTIONS",
            "PRACK",
            "PUBLISH",
            "REFER",
            "REGISTER",
            "SUBSCRIBE",
            "UPDATE",
        ];
        let named: Vec<&str> = REGISTRY
            .iter()
            .copied()
            .filter(|m| !matches!(SipMethod::parse(m), SipMethod::Custom(_)))
            .collect();
        assert_eq!(
            named.len(),
            REGISTRY.len(),
            "these registered methods parse as Custom and would fall to the \
             generic dialog handler: {:?}",
            REGISTRY
                .iter()
                .filter(|m| matches!(SipMethod::parse(m), SipMethod::Custom(_)))
                .collect::<Vec<_>>()
        );

        // And nothing beyond the registry: every named variant round-trips to a
        // registered token. A variant with no registry entry is either a typo or
        // an extension that needs saying so out loud.
        for token in REGISTRY {
            let m = SipMethod::parse(token);
            assert_eq!(
                m.as_str(),
                token,
                "{token} does not round-trip through SipMethod"
            );
        }
    }

    use super::*;

    /// Every standard method string parses to its dedicated variant.
    #[test]
    fn parse_known_methods() {
        assert_eq!(SipMethod::parse("INVITE"), SipMethod::Invite);
        assert_eq!(SipMethod::parse("ACK"), SipMethod::Ack);
        assert_eq!(SipMethod::parse("BYE"), SipMethod::Bye);
        assert_eq!(SipMethod::parse("CANCEL"), SipMethod::Cancel);
        assert_eq!(SipMethod::parse("REGISTER"), SipMethod::Register);
        assert_eq!(SipMethod::parse("OPTIONS"), SipMethod::Options);
        assert_eq!(SipMethod::parse("PRACK"), SipMethod::Prack);
        assert_eq!(SipMethod::parse("SUBSCRIBE"), SipMethod::Subscribe);
        assert_eq!(SipMethod::parse("NOTIFY"), SipMethod::Notify);
        assert_eq!(SipMethod::parse("PUBLISH"), SipMethod::Publish);
        assert_eq!(SipMethod::parse("INFO"), SipMethod::Info);
        assert_eq!(SipMethod::parse("REFER"), SipMethod::Refer);
        assert_eq!(SipMethod::parse("MESSAGE"), SipMethod::Message);
        assert_eq!(SipMethod::parse("UPDATE"), SipMethod::Update);
    }

    /// An unknown method round-trips through `Custom` and keeps its name.
    #[test]
    fn parse_custom_method() {
        let m = SipMethod::parse("XYZZY");
        assert_eq!(m, SipMethod::Custom("XYZZY".into()));
        assert_eq!(m.as_str(), "XYZZY");
    }

    /// `Display` output equals `as_str` for both standard and custom methods.
    #[test]
    fn display_matches_as_str() {
        assert_eq!(SipMethod::Invite.to_string(), "INVITE");
        assert_eq!(SipMethod::Custom("FOO".into()).to_string(), "FOO");
    }

    /// Methods order lexicographically by canonical name (ACK < INVITE).
    #[test]
    fn ordering() {
        assert!(SipMethod::Ack < SipMethod::Invite);
        assert!(SipMethod::Bye < SipMethod::Cancel);
    }

    /// `SipMethod == str` compares against the canonical string form.
    #[test]
    fn partial_eq_str() {
        assert!(SipMethod::Invite == *"INVITE");
        assert!(SipMethod::Bye == *"BYE");
        assert!(SipMethod::Custom("FOO".into()) == *"FOO");
    }
}
