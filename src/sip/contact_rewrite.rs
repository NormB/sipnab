// SPDX-License-Identifier: MIT OR Apache-2.0

//! Whether a registrar rewrote a private `Contact`, or left traffic
//! undeliverable.
//!
//! A phone behind NAT puts its own private address in the `Contact` of a
//! REGISTER. The registrar is supposed to notice — the packet arrived from a
//! public address that is not the one in the header — and route later requests
//! to where the packet came from rather than to what the header claims. When
//! it does, everything works. When it does not, every inbound call to that
//! phone is addressed to an unroutable host and the phone simply never rings.
//!
//! # Why the observation is not the finding
//!
//! **A private `Contact` from a public source is normal, not a fault.**
//! Measured against the private corpus on 2026-09-08: 1,660 of 2,226 REGISTER
//! contacts carry a private host — 74.6% — and the fleet those registrations
//! belong to is working. A rule that fired on the observation alone would
//! report three quarters of a healthy estate.
//!
//! What separates the working case from the broken one is what happened NEXT:
//! whether later requests to that endpoint went to the address the packet came
//! from, or to the address the header claimed. So the observation is reported
//! wherever a single dialog can see it, and the FINDING waits for corroboration
//! that only a cross-dialog view has.

use serde::Serialize;

/// What one REGISTER's `Contact` said, against where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct ContactObservation {
    /// The host the `Contact` header named, when it named an address.
    ///
    /// `None` for a `Contact` naming a domain rather than an address: a name
    /// resolves somewhere this capture cannot see, so calling it private or
    /// public would be a guess.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_host: Option<String>,
    /// Whether that host is one the public internet does not route to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_host_private: Option<bool>,
    /// Whether the REGISTER arrived from a public address.
    pub source_public: bool,
    /// The two together: the shape a NAT rewrite is required for.
    ///
    /// Reported as its own field rather than left for a reader to compute,
    /// because it is the thing every consumer wants and computing it twice is
    /// how two surfaces come to disagree.
    pub rewrite_required: bool,
}

/// What later traffic did about the address the registrar was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[serde(rename_all = "kebab-case")]
pub enum RewriteVerdict {
    /// Later requests went to the address the REGISTER arrived from. The
    /// registrar did its job and nothing is wrong.
    Rewritten,
    /// Later requests went to the private host the `Contact` claimed. Those
    /// requests are addressed to somewhere the public internet does not route
    /// to, and the phone never sees them.
    NotRewritten,
    /// No later requests to this endpoint in the capture, so the question is
    /// open. Distinct from `Rewritten` on purpose: silence is not success, and
    /// reporting it as one is how a capture that ended too early reads as a
    /// clean bill of health.
    NoLaterRequests,
}

/// The corroborated answer for one endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct ContactRewriteFinding {
    /// The observation, from the REGISTER.
    pub observation: ContactObservation,
    /// What later traffic did about it.
    pub verdict: RewriteVerdict,
    /// Later requests addressed to the private `Contact` host.
    pub requests_to_contact: usize,
    /// Later requests addressed to the source the REGISTER arrived from.
    pub requests_to_source: usize,
    /// True only for the conjunction: a rewrite was required and did not
    /// happen. This is the field a consumer should alert on.
    pub is_finding: bool,
}

/// Read one REGISTER's `Contact` host against the address it arrived from.
///
/// `contact_host` is the host part as written, so a name stays a name: a
/// `Contact` naming a domain resolves somewhere this capture cannot see, and
/// calling it private would invent a fault while calling it public would clear
/// one. Neither is a measurement, so it is reported unjudged.
#[must_use]
pub fn observe(contact_host: Option<&str>, source: std::net::IpAddr) -> ContactObservation {
    let source_public = !crate::net::is_private_address(source) && !source.is_loopback();
    let contact_host_private = contact_host
        .and_then(host_address)
        .map(crate::net::is_private_address);
    ContactObservation {
        contact_host: contact_host.map(str::to_string),
        contact_host_private,
        source_public,
        // Only the conjunction. A private Contact reaching a registrar on its
        // own network needs nothing rewritten, and a public Contact needs
        // nothing rewritten from anywhere.
        rewrite_required: contact_host_private == Some(true) && source_public,
    }
}

/// The address a `Contact` host names, if it names one rather than a domain.
///
/// Public because the corroboration needs the same reading of the same host:
/// deciding privacy one way here and matching destinations another way there
/// is how two halves of one rule come to disagree.
///
/// Strips the port and the IPv6 brackets before parsing, because `[2001:db8::1]:5060`
/// and `192.0.2.1:5060` are both what a `Contact` really carries.
pub fn host_address(host: &str) -> Option<std::net::IpAddr> {
    let host = host.trim();
    if let Some(inner) = host.strip_prefix('[') {
        let (addr, _) = inner.split_once(']')?;
        return addr.parse().ok();
    }
    // A bare IPv6 literal has several colons; only a single trailing colon is
    // a port separator.
    let candidate = match host.rsplit_once(':') {
        Some((left, right)) if right.chars().all(|c| c.is_ascii_digit()) && !left.contains(':') => {
            left
        }
        _ => host,
    };
    candidate.parse().ok()
}

/// The host part of a `Contact` header's URI.
///
/// `Contact: <sip:alice@192.168.1.50:5060;transport=udp>` yields
/// `192.168.1.50:5060`, which [`observe`] then splits. Parsed here rather than
/// with a general URI parser because only the host is wanted and a `Contact`
/// carries display names, angle brackets and header parameters that a
/// general parse would have to be told to ignore anyway.
///
/// Returns `None` for `Contact: *`, which RFC 3261 §10.2.2 defines as "every
/// binding" on a de-registration and names no host at all.
#[must_use]
pub fn contact_host(header: &str) -> Option<&str> {
    let value = header.trim();
    if value.starts_with('*') {
        return None;
    }
    // The URI is inside angle brackets when a display name is present, and
    // bare otherwise. Take the bracketed form first: a display name may itself
    // contain something that looks like a URI.
    let uri = match value.split_once('<') {
        Some((_, rest)) => rest.split_once('>').map(|(u, _)| u)?,
        None => value.split(';').next()?,
    };
    let after_scheme = uri.split_once(':').map(|(_, r)| r).unwrap_or(uri);
    // A `user@host` split, when there is a user part.
    let hostport = after_scheme
        .rsplit_once('@')
        .map_or(after_scheme, |(_, h)| h);
    // Stop at a URI parameter or header.
    let host = hostport.split([';', '?']).next()?.trim();
    (!host.is_empty()).then_some(host)
}

/// Settle an observation against what later requests actually did.
///
/// `requests_to_contact` and `requests_to_source` count later requests
/// addressed to the private `Contact` host and to the address the REGISTER
/// arrived from. They are passed in rather than looked up, because only a
/// cross-dialog view holds them and this rule has to be drivable from a test
/// without one.
#[must_use]
pub fn corroborate(
    observation: ContactObservation,
    requests_to_contact: usize,
    requests_to_source: usize,
) -> ContactRewriteFinding {
    // ANY request to the private host is a request nobody receives. Reading
    // the majority would hide a partial failure behind a working one: 99
    // deliverable requests do not make the hundredth deliverable.
    let verdict = if requests_to_contact > 0 {
        RewriteVerdict::NotRewritten
    } else if requests_to_source > 0 {
        RewriteVerdict::Rewritten
    } else {
        RewriteVerdict::NoLaterRequests
    };
    ContactRewriteFinding {
        is_finding: observation.rewrite_required && verdict == RewriteVerdict::NotRewritten,
        observation,
        verdict,
        requests_to_contact,
        requests_to_source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().expect("fixture address")
    }

    /// The host comes out of the real header shapes a `Contact` carries.
    #[test]
    fn the_contact_host_is_read_out_of_every_shape_the_header_takes() {
        for (header, want) in [
            ("<sip:alice@192.168.1.50:5060>", Some("192.168.1.50:5060")),
            ("\"Alice\" <sip:alice@192.168.1.50>", Some("192.168.1.50")),
            ("sip:alice@192.168.1.50", Some("192.168.1.50")),
            (
                "<sip:alice@192.168.1.50;transport=udp>",
                Some("192.168.1.50"),
            ),
            (
                "<sip:alice@192.168.1.50>;expires=3600",
                Some("192.168.1.50"),
            ),
            ("<sip:192.168.1.50>", Some("192.168.1.50")),
            ("<sip:alice@[2001:db8::1]:5060>", Some("[2001:db8::1]:5060")),
            // RFC 3261 section 10.2.2: `*` is every binding, and names no host.
            ("*", None),
        ] {
            assert_eq!(contact_host(header), want, "header {header:?}");
        }
    }

    /// An address is recovered from a host that carries a port or brackets.
    #[test]
    fn a_port_or_brackets_do_not_hide_the_address() {
        for (host, private) in [
            ("192.168.1.50", true),
            ("192.168.1.50:5060", true),
            ("[fd00::1]:5060", true),
            ("[2001:db8::1]", false),
            ("198.51.100.7:5060", false),
        ] {
            let o = observe(Some(host), ip("203.0.113.9"));
            assert_eq!(
                o.contact_host_private,
                Some(private),
                "host {host:?} should read as private={private}"
            );
        }
    }

    /// The shape a rewrite is required for.
    #[test]
    fn a_private_contact_from_a_public_source_requires_a_rewrite() {
        let o = observe(Some("192.168.1.50"), ip("203.0.113.9"));
        assert_eq!(o.contact_host.as_deref(), Some("192.168.1.50"));
        assert_eq!(o.contact_host_private, Some(true));
        assert!(o.source_public);
        assert!(o.rewrite_required);
    }

    /// A private contact from a private source is a phone talking to a
    /// registrar on its own network. Nothing has to be rewritten.
    #[test]
    fn a_private_contact_from_a_private_source_requires_nothing() {
        let o = observe(Some("192.168.1.50"), ip("192.168.1.1"));
        assert_eq!(o.contact_host_private, Some(true));
        assert!(!o.source_public);
        assert!(!o.rewrite_required);
    }

    /// A public contact needs no rewrite whatever the source.
    #[test]
    fn a_public_contact_requires_nothing() {
        for source in ["203.0.113.9", "192.168.1.1"] {
            let o = observe(Some("198.51.100.7"), ip(source));
            assert_eq!(o.contact_host_private, Some(false));
            assert!(!o.rewrite_required, "source {source}");
        }
    }

    /// A `Contact` naming a domain is not judged.
    ///
    /// A name resolves somewhere this capture cannot see. Calling it private
    /// would invent a fault and calling it public would clear one, and neither
    /// is a measurement.
    #[test]
    fn a_contact_naming_a_domain_is_not_judged() {
        let o = observe(Some("pbx.example.com"), ip("203.0.113.9"));
        assert_eq!(o.contact_host.as_deref(), Some("pbx.example.com"));
        assert_eq!(o.contact_host_private, None);
        assert!(
            !o.rewrite_required,
            "an unresolvable host cannot be said to require a rewrite"
        );
    }

    /// The finding needs the conjunction, not the observation.
    ///
    /// This is the whole point. 74.6% of REGISTER contacts in the private
    /// corpus are private and that estate works; firing on the observation
    /// would report three quarters of it as broken.
    #[test]
    fn the_finding_needs_later_traffic_to_confirm_it() {
        let o = observe(Some("192.168.1.50"), ip("203.0.113.9"));
        assert!(o.rewrite_required, "the fixture is the at-risk shape");

        // The registrar rewrote: later requests went to the public source.
        let good = corroborate(o.clone(), 0, 12);
        assert_eq!(good.verdict, RewriteVerdict::Rewritten);
        assert!(
            !good.is_finding,
            "a rewrite that happened is not a fault, however private the \
             Contact was"
        );

        // The registrar did not: later requests went to the private host.
        let bad = corroborate(o.clone(), 9, 0);
        assert_eq!(bad.verdict, RewriteVerdict::NotRewritten);
        assert!(bad.is_finding);

        // Nothing later at all: the question is open, and open is not clean.
        let quiet = corroborate(o, 0, 0);
        assert_eq!(quiet.verdict, RewriteVerdict::NoLaterRequests);
        assert!(
            !quiet.is_finding,
            "silence is not evidence of a fault either -- a capture that ended \
             before the first inbound call says nothing"
        );
    }

    /// Traffic to both is reported as not rewritten.
    ///
    /// A proxy that sends some requests to the source and some to the header
    /// still sends some nobody receives. Reading the majority would hide a
    /// partial failure behind a working one.
    #[test]
    fn any_traffic_to_the_private_contact_is_a_finding() {
        let o = observe(Some("192.168.1.50"), ip("203.0.113.9"));
        let split = corroborate(o, 1, 99);
        assert_eq!(split.verdict, RewriteVerdict::NotRewritten);
        assert!(
            split.is_finding,
            "99 deliverable requests do not make the one undeliverable request \
             deliverable"
        );
    }

    /// An observation that never required a rewrite is never a finding,
    /// whatever later traffic did.
    #[test]
    fn no_rewrite_required_means_no_finding_whatever_follows() {
        let o = observe(Some("198.51.100.7"), ip("203.0.113.9"));
        for (to_contact, to_source) in [(0, 0), (5, 0), (0, 5), (5, 5)] {
            let f = corroborate(o.clone(), to_contact, to_source);
            assert!(
                !f.is_finding,
                "a public Contact needed no rewrite, so nothing later can make \
                 its absence a fault ({to_contact}/{to_source})"
            );
        }
    }
}
