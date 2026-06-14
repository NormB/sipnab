//! SIP response code explanations.
//!
//! Provides human-readable descriptions and common causes for SIP response
//! codes, useful for diagnostics and the TUI display.

/// Returns a human-readable explanation and common causes for a SIP response code.
///
/// Coverage includes all commonly encountered codes from RFC 3261 and key
/// extensions. Returns `None` for unrecognized codes.
///
/// # Examples
///
/// ```
/// use sipnab::sip::response_codes::explain_response_code;
///
/// assert!(explain_response_code(200).unwrap().contains("OK"));
/// assert!(explain_response_code(299).is_none());
/// ```
pub fn explain_response_code(code: u16) -> Option<&'static str> {
    match code {
        // 1xx — Provisional
        100 => Some(
            "100 Trying — Request received, being processed. \
             The next hop is working on it; no action needed yet.",
        ),
        180 => Some(
            "180 Ringing — The callee's device is alerting (ringing). \
             The call is progressing normally.",
        ),
        181 => Some(
            "181 Call Is Being Forwarded — The call is being redirected \
             to another destination by the server.",
        ),
        182 => Some(
            "182 Queued — The callee is temporarily unavailable; the call \
             has been queued for later delivery.",
        ),
        183 => Some(
            "183 Session Progress — Early media or progress information. \
             Often carries SDP for early media (ringback tones, IVR prompts).",
        ),
        199 => Some(
            "199 Early Dialog Terminated — An early dialog was terminated \
             before the final response (RFC 6228).",
        ),

        // 2xx — Success
        200 => Some(
            "200 OK — Request succeeded. For INVITE, the call is established; \
             for REGISTER, the binding is active.",
        ),
        202 => Some(
            "202 Accepted — Request accepted for processing but not yet completed. \
             Used with REFER and SUBSCRIBE.",
        ),
        204 => Some(
            "204 No Notification — SUBSCRIBE accepted but no NOTIFY will be sent \
             (RFC 5839).",
        ),

        // 3xx — Redirection
        300 => Some(
            "300 Multiple Choices — The Request-URI resolves to multiple locations. \
             The client should retry with one of the alternatives.",
        ),
        301 => Some(
            "301 Moved Permanently — The user has permanently moved. \
             Update the address of record and retry.",
        ),
        302 => Some(
            "302 Moved Temporarily — The user is temporarily at a different \
             location. Retry at the Contact URI.",
        ),
        305 => Some(
            "305 Use Proxy — The request must be sent through the specified proxy. \
             Check the Contact header for the proxy URI.",
        ),
        380 => Some(
            "380 Alternative Service — The call failed but an alternative service \
             is available (e.g., voicemail).",
        ),

        // 4xx — Client Errors
        400 => Some(
            "400 Bad Request — The request is malformed. Check syntax, missing \
             mandatory headers, or invalid URI format.",
        ),
        401 => Some(
            "401 Unauthorized — Authentication required by the UAS. \
             Re-send with Authorization header. Check credentials.",
        ),
        402 => Some(
            "402 Payment Required — Reserved for future use. \
             Some implementations use it for billing/quota enforcement.",
        ),
        403 => Some(
            "403 Forbidden — The server understood the request but refuses \
             to fulfill it. Check ACLs, IP allow lists, or domain policy.",
        ),
        404 => Some(
            "404 Not Found — The user does not exist at the domain. \
             Verify the Request-URI and check registration status.",
        ),
        405 => Some(
            "405 Method Not Allowed — The SIP method is not supported by the \
             server. Check the Allow header in the response.",
        ),
        406 => Some(
            "406 Not Acceptable — Cannot generate a response matching the \
             client's Accept header constraints.",
        ),
        407 => Some(
            "407 Proxy Authentication Required — The proxy requires credentials. \
             Re-send with Proxy-Authorization header.",
        ),
        408 => Some(
            "408 Request Timeout — The server could not produce a response in \
             time. The callee may be unreachable or unresponsive.",
        ),
        409 => Some(
            "409 Conflict — The request conflicts with the current state of \
             the resource.",
        ),
        410 => Some(
            "410 Gone — The user existed but is no longer available at this \
             server and no forwarding address is known.",
        ),
        412 => Some(
            "412 Conditional Request Failed — The precondition in the request \
             (If-Match) was not met (RFC 3903).",
        ),
        413 => Some(
            "413 Request Entity Too Large — The request body (typically SDP) \
             exceeds the server's size limit.",
        ),
        414 => Some(
            "414 Request-URI Too Long — The Request-URI is longer than the \
             server is willing to process.",
        ),
        415 => Some(
            "415 Unsupported Media Type — The body Content-Type is not supported. \
             Check Content-Type and Accept headers.",
        ),
        416 => Some(
            "416 Unsupported URI Scheme — The Request-URI scheme (e.g., tel:) \
             is not supported by the server.",
        ),
        417 => Some(
            "417 Unknown Resource-Priority — The Resource-Priority value is not \
             understood by the server.",
        ),
        420 => Some(
            "420 Bad Extension — A required extension (Require header) is not \
             supported. Check the Unsupported header in the response.",
        ),
        421 => Some(
            "421 Extension Required — The server needs a specific extension \
             that the client did not indicate.",
        ),
        422 => Some(
            "422 Session Interval Too Small — The Session-Expires value is \
             below the minimum. Check Min-SE header in the response.",
        ),
        423 => Some(
            "423 Interval Too Brief — The registration expiration is too short. \
             Check Min-Expires header in the response.",
        ),
        428 => Some(
            "428 Use Identity Header — The server requires an Identity header \
             for the request (RFC 4474).",
        ),
        429 => Some(
            "429 Provide Referrer Identity — A REFER request needs a valid \
             Referred-By header (RFC 3892).",
        ),
        433 => Some(
            "433 Anonymity Disallowed — The server rejected the request because \
             the caller's identity was hidden (RFC 5079).",
        ),
        436 => Some(
            "436 Bad Identity-Info — The Identity-Info header URI is invalid \
             or dereferences to an unusable document.",
        ),
        437 => Some(
            "437 Unsupported Certificate — The certificate referenced by \
             Identity-Info cannot be validated.",
        ),
        438 => Some(
            "438 Invalid Identity Header — The Identity header signature \
             verification failed.",
        ),
        439 => Some(
            "439 First Hop Lacks Outbound Support — The first outbound proxy \
             does not support the outbound mechanism (RFC 5626).",
        ),
        440 => Some(
            "440 Max-Breadth Exceeded — The request exceeded the maximum \
             number of parallel forks allowed.",
        ),
        469 => Some(
            "469 Bad Info Package — The Info-Package in the request is not \
             supported (RFC 6086).",
        ),
        470 => Some(
            "470 Consent Needed — The request requires consent from the \
             target URI (RFC 5360).",
        ),
        480 => Some(
            "480 Temporarily Unavailable — The callee is currently not reachable. \
             They may be offline, DND, or have no active registrations.",
        ),
        481 => Some(
            "481 Call/Transaction Does Not Exist — The server received a request \
             for a dialog or transaction it has no record of. \
             Common after restarts or missed ACKs.",
        ),
        482 => Some(
            "482 Loop Detected — The server detected a forwarding loop. \
             Check Via headers and routing rules.",
        ),
        483 => Some(
            "483 Too Many Hops — Max-Forwards reached zero. The request passed \
             through too many proxies.",
        ),
        484 => Some(
            "484 Address Incomplete — The Request-URI is incomplete. Common with \
             overlap dialing; check collected digits.",
        ),
        485 => Some(
            "485 Ambiguous — The Request-URI is ambiguous; multiple users match. \
             Check the Contact header for alternatives.",
        ),
        486 => Some(
            "486 Busy Here — The callee is currently busy on another call. \
             Try again later or enable call waiting.",
        ),
        487 => Some(
            "487 Request Terminated — The request was cancelled by a CANCEL or \
             replaced by a new request (BYE/re-INVITE). Normal flow.",
        ),
        488 => Some(
            "488 Not Acceptable Here — Codec negotiation failed. Compare the SDP \
             offer against the callee's supported codecs and ptime values.",
        ),
        489 => Some(
            "489 Bad Event — The Event header value is not supported by the \
             server. Check the Allow-Events header.",
        ),
        491 => Some(
            "491 Request Pending — The server has a pending request for the same \
             dialog. Retry after a short delay (RFC 3261 SS14.1).",
        ),
        493 => Some(
            "493 Undecipherable — The S/MIME body could not be decrypted. \
             Check certificates and encryption settings.",
        ),
        494 => Some(
            "494 Security Agreement Required — The client must initiate a \
             security agreement (RFC 3329).",
        ),

        // 5xx — Server Errors
        500 => Some(
            "500 Server Internal Error — An unexpected condition prevented the \
             server from fulfilling the request. Check server logs.",
        ),
        501 => Some(
            "501 Not Implemented — The SIP method or feature is not implemented \
             by the server.",
        ),
        502 => Some(
            "502 Bad Gateway — The server received an invalid response from a \
             downstream server while acting as a gateway or proxy.",
        ),
        503 => Some(
            "503 Service Unavailable — The server is overloaded or under \
             maintenance. Check Retry-After header. May also indicate \
             no available routes to the destination.",
        ),
        504 => Some(
            "504 Server Timeout — The server did not receive a timely response \
             from an upstream server. Check connectivity to next hops.",
        ),
        505 => Some(
            "505 Version Not Supported — The SIP version in the request is not \
             supported. Must be SIP/2.0.",
        ),
        513 => Some(
            "513 Message Too Large — The request message is larger than the \
             server can process.",
        ),
        555 => Some(
            "555 Push Notification Service Not Supported — The server does not \
             support the push notification service specified (RFC 8599).",
        ),
        580 => Some(
            "580 Precondition Failure — A precondition for the request was not \
             met (RFC 3312).",
        ),

        // 6xx — Global Failures
        600 => Some(
            "600 Busy Everywhere — The callee is busy and does not wish to take \
             the call at any location. All known endpoints declined.",
        ),
        603 => Some(
            "603 Decline — The callee explicitly declined the call. This is \
             distinct from busy; the user chose to reject it.",
        ),
        604 => Some(
            "604 Does Not Exist Anywhere — The Request-URI does not exist \
             anywhere in the network. Authoritative rejection.",
        ),
        606 => Some(
            "606 Not Acceptable — Some aspect of the session description is \
             unacceptable. Check the Warning header for specifics.",
        ),
        607 => Some(
            "607 Unwanted — The callee rejected the call as unwanted/spam \
             (RFC 8197). Consider STIR/SHAKEN validation.",
        ),
        608 => Some(
            "608 Rejected — The call was rejected by an intermediary due to \
             policy. Similar to 607 but applied by network, not callee.",
        ),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_have_explanations() {
        assert!(explain_response_code(200).unwrap().contains("OK"));
        assert!(explain_response_code(404).unwrap().contains("Not Found"));
        assert!(
            explain_response_code(488)
                .unwrap()
                .contains("Codec negotiation")
        );
        assert!(
            explain_response_code(503)
                .unwrap()
                .contains("Service Unavailable")
        );
    }

    #[test]
    fn provisional_codes() {
        assert!(explain_response_code(100).unwrap().contains("Trying"));
        assert!(explain_response_code(180).unwrap().contains("Ringing"));
        assert!(
            explain_response_code(183)
                .unwrap()
                .contains("Session Progress")
        );
    }

    #[test]
    fn common_error_codes() {
        assert!(explain_response_code(401).unwrap().contains("Unauthorized"));
        assert!(explain_response_code(403).unwrap().contains("Forbidden"));
        assert!(explain_response_code(407).unwrap().contains("Proxy"));
        assert!(
            explain_response_code(480)
                .unwrap()
                .contains("Temporarily Unavailable")
        );
        assert!(explain_response_code(486).unwrap().contains("Busy"));
        assert!(explain_response_code(487).unwrap().contains("Terminated"));
        assert!(explain_response_code(491).unwrap().contains("Pending"));
    }

    #[test]
    fn global_failure_codes() {
        assert!(
            explain_response_code(600)
                .unwrap()
                .contains("Busy Everywhere")
        );
        assert!(explain_response_code(603).unwrap().contains("Decline"));
        assert!(
            explain_response_code(604)
                .unwrap()
                .contains("Does Not Exist")
        );
        assert!(
            explain_response_code(606)
                .unwrap()
                .contains("Not Acceptable")
        );
    }

    #[test]
    fn unknown_code_returns_none() {
        assert!(explain_response_code(299).is_none());
        assert!(explain_response_code(999).is_none());
        assert!(explain_response_code(0).is_none());
    }

    /// Every response code with an implemented explanation. Keep in sync with
    /// the `match` arms above — the table-driven tests below assert this list
    /// is exactly the set of codes that return `Some`.
    const IMPLEMENTED_CODES: &[u16] = &[
        // 1xx
        100, 180, 181, 182, 183, 199, //
        // 2xx
        200, 202, 204, //
        // 3xx
        300, 301, 302, 305, 380, //
        // 4xx
        400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 412, 413, 414, 415, 416, 417, 420,
        421, 422, 423, 428, 429, 433, 436, 437, 438, 439, 440, 469, 470, 480, 481, 482, 483, 484,
        485, 486, 487, 488, 489, 491, 493, 494, //
        // 5xx
        500, 501, 502, 503, 504, 505, 513, 555, 580, //
        // 6xx
        600, 603, 604, 606, 607, 608,
    ];

    #[test]
    fn every_implemented_code_starts_with_its_number_and_is_nonempty() {
        for &code in IMPLEMENTED_CODES {
            let text = explain_response_code(code)
                .unwrap_or_else(|| panic!("code {code} should have an explanation"));
            // Each explanation opens with the numeric code, e.g. "404 Not Found …".
            assert!(
                text.starts_with(&code.to_string()),
                "explanation for {code} should start with the code, got: {text:?}"
            );
            // No stray empty/whitespace-only entries, and an em-dash separator.
            assert!(text.trim().len() > 5, "explanation for {code} too short");
            assert!(
                text.contains('—'),
                "explanation for {code} missing em-dash separator: {text:?}"
            );
        }
    }

    #[test]
    fn implemented_set_is_exactly_the_codes_returning_some() {
        // Sweep the entire u16 response-code space: a code returns Some iff it
        // is in IMPLEMENTED_CODES. Guards against a typo'd or duplicated arm.
        for code in 0u16..=1000 {
            let is_listed = IMPLEMENTED_CODES.contains(&code);
            assert_eq!(
                explain_response_code(code).is_some(),
                is_listed,
                "code {code}: listed={is_listed} but Some={}",
                explain_response_code(code).is_some()
            );
        }
    }

    #[test]
    fn unimplemented_and_boundary_codes_return_none() {
        // Boundaries just outside real classes, plus reserved/unused codes.
        for &code in &[
            0u16, 1, 99, 101, 150, 184, 198, 201, 203, 205, 299, 303, 399, 411, 418, 430, 490, 499,
            511, 599, 601, 605, 699, 700, 999, 1000,
        ] {
            assert!(
                explain_response_code(code).is_none(),
                "code {code} should be unimplemented (None)"
            );
        }
    }
}
