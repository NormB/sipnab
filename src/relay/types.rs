// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a media relay's answer looks like, independent of which relay gave it.
//!
//! These types were defined inside `src/rtpengine/control.rs`, next to the
//! parser that fills them from rtpengine's ng wire format. That put a shape
//! every relay produces behind a name only one relay owns, and it is the
//! boundary RP2 is about: `EndpointAssertion::relay_asserted` and `Reconciler`
//! were never rtpengine-specific, the module they lived in was.
//!
//! Nothing here knows about bencode, ng, or a cookie. A second control decoder
//! parses its own wire format into these same types and the reconciler above it
//! cannot tell which one answered -- which is the point, and is what
//! `relay_seam_test` holds in place.

/// A command that only reads. There is deliberately no way to say anything
/// else.
///
/// See the module note: the point is not that sipnab avoids sending `delete`,
/// it is that this type cannot express it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOnlyCommand {
    /// Every active Call-ID the relay knows, bounded by `limit`.
    ///
    /// rtpengine defaults to 32 and warns that raising it may exceed a UDP
    /// datagram, which is why [`crate::rtpengine::control::ControlRequest`] carries whether the answer
    /// was complete.
    List {
        /// How many Call-IDs to ask for.
        limit: u32,
    },
    /// One call's tags and streams.
    Query {
        /// The Call-ID to ask about.
        call_id: String,
    },
}
/// What a `list` answered, and whether it answered fully.
///
/// The completeness flag is not decoration. rtpengine returns 32 Call-IDs by
/// default; covering 32 of 400 calls and saying nothing reports the other 368
/// as orphans and looks exactly like a run that worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumeration {
    /// The Call-IDs the relay returned.
    pub call_ids: Vec<String>,
    /// Whether the relay had more than it returned.
    pub truncated: bool,
}
/// What a relay answered, decoded from its reply.
///
/// rtpengine answers `{"result": "ok", ...}` or `{"result": "error", ...}`.
/// An error is not a transport failure and must not be reported as one: the
/// relay was reached, understood the question, and declined it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlReply {
    /// A `list` answer.
    Calls(Enumeration),
    /// A `query` answer: one call, as the relay holds it.
    Call(CallView),
    /// The relay refused, with its own words.
    Refused {
        /// What the relay said.
        reason: String,
    },
}
/// A client for one relay's control socket.
///
/// # Why the address is a constructor argument
///
/// It is never inferred from capture traffic. The address sipnab could guess
/// is one it learned from packets, and sending to an address derived from a
/// capture is how an analysis tool starts talking to a stranger -- a host that
/// was a relay when the capture was taken, and is somebody's laptop now.
///
/// # Why there is no `run` method
///
/// RE4 requires this to be triggered at startup and when an unexplained stream
/// appears, and NEVER to poll. There is no loop here and no timer: a caller who
/// wants periodic behavior has to write the loop themselves, which is a
/// visible act rather than a default. A poller is a service, and a service that
/// talks to a production relay is something an operator opts into.
/// One relay-side port, and who the relay exchanges media with on it.
///
/// This is the join key an unexplained stream needs. sipnab sees packets
/// arriving at the relay's own address and port; the relay is the only thing
/// that knows which call that port was allocated for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStream {
    /// The relay's own address for this stream, as it appears on the wire.
    pub local_address: String,
    /// The relay's own port. The half sipnab can see without any signaling.
    pub local_port: u16,
    /// Where the relay currently sends, once it has learned it.
    pub endpoint: Option<String>,
    /// What the far side advertised in SDP, which may differ from `endpoint`
    /// behind NAT -- and the difference is often the bug being chased.
    pub advertised_endpoint: Option<String>,
    /// Whether this port carries RTCP rather than RTP, from the relay's flags.
    pub is_rtcp: bool,
    /// Every SSRC the relay has seen on this port, ingress and egress.
    ///
    /// A second join key, and a better one where a capture is taken off-path
    /// from the relay: an SSRC follows the media even when the addresses do
    /// not survive the path.
    pub ssrcs: Vec<u32>,
}
/// One side of a call, as the relay holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTag {
    /// The SIP tag identifying this side.
    pub tag: String,
    /// The tags this side exchanges media with.
    pub in_dialogue_with: Vec<String>,
    /// The codec the relay recorded for this side, where it recorded one.
    pub codec: Option<String>,
    /// Ports the relay holds for this side, RTP and RTCP together.
    pub streams: Vec<RelayStream>,
}
/// What a relay knows about one call.
///
/// The Call-ID is carried from the REQUEST, not read from the reply: a
/// rtpengine `query` answer does not echo the Call-ID it was asked about
/// (verified against 12.5.1), so pairing the answer with its question is the
/// caller's job and cannot be checked from the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallView {
    /// The Call-ID this view answers for, from the request.
    pub call_id: String,
    /// Each side of the call.
    pub tags: Vec<RelayTag>,
}
