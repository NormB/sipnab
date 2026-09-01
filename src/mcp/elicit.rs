// SPDX-License-Identifier: MIT OR Apache-2.0

//! `elicitation/create`: asking a PERSON before an irreversible act (PB6).
//!
//! Two tools do something no later call can undo. `shutdown_server` ends the
//! run. `open_capture` clears every dialog and stream the process holds, so
//! every Call-ID, cursor and message index an agent has collected addresses a
//! capture that no longer exists.
//!
//! Both were guarded by a CONVENTION: a `dry_run` argument defaulting to the
//! safe value, so stopping took a deliberate second call. That was the right
//! call while it was the only one available, and it has a structural hole —
//! the deliberate second call is made by the same agent that made the first,
//! from the same reasoning that produced it. A model that has decided to stop
//! the server passes `dry_run=false` on the retry as readily as it passed the
//! default on the first attempt. The convention rate-limits an accident; it
//! does not introduce a second party.
//!
//! Elicitation does. `elicitation/create` is a server-to-client REQUEST: the
//! handler stops, the client puts the question to whoever is driving it, and
//! the answer comes back as a response before the tool call is answered. That
//! is a real round trip to a human, which is the property the convention could
//! not have.
//!
//! # The convention stays, because the round trip is not always available
//!
//! Elicitation is a CLIENT capability, declared at `initialize`. A client that
//! did not declare it must never be sent the request — and, more importantly,
//! sipnab must not treat the absence as a refusal, or a stock client would
//! find `shutdown_server` newly impossible. So [`Confirm::to`] reads what the
//! peer advertised and the handlers fall back to exactly the behavior that
//! existed before this module: `dry_run` for `shutdown_server`, and
//! `--mcp-allow-open-capture` for the swap. The convention is now the FLOOR
//! rather than the ceiling.
//!
//! # Why this is not built on `Peer::elicit`
//!
//! rmcp 3.1.4 ships typed helpers — `Peer::<RoleServer>::elicit::<T>()` and
//! `create_elicitation` — behind its `elicitation` cargo feature, which also
//! pulls `dep:url` for the URL-mode variant sipnab has no use for. The request
//! and result MODELS (`ElicitRequest`, `ElicitRequestParams`, `ElicitResult`,
//! `ElicitationSchema`) are not behind that feature, and neither is
//! `Peer::send_request`, which is what those helpers expand to: one
//! `ServerRequest::ElicitRequest` sent and one `ClientResult::ElicitResult`
//! matched. Sending it directly is the same wire exchange under the same
//! SEP-2260 request-association enforcement, without adding a feature and a
//! dependency to reach a two-line wrapper.
//!
//! # One question, asked one way
//!
//! Every confirmation is a form with a single required boolean named
//! [`CONFIRM_FIELD`]. A schema per tool would let one of them come to ask
//! something the handler does not read, and a tool that ignores the answer it
//! asked for is worse than one that never asked.

use rmcp::RoleServer;
use rmcp::model::{
    ClientResult, ElicitRequest, ElicitRequestParams, ElicitationAction, ElicitationSchema,
    ServerRequest,
};

/// The single field every confirmation form asks for.
///
/// Named once because two places read it: the schema sipnab sends and the
/// content it reads back. A form asking for `confirm` whose answer is read
/// from `confirmed` would take every accepted confirmation as a refusal, and
/// the tool would look like it was working.
pub const CONFIRM_FIELD: &str = "confirm";

/// Whether a client that advertised `capabilities` can answer a FORM.
///
/// The spec's reading, in one place: a client that declared `elicitation` with
/// neither `form` nor `url` predates the split and means form, a client that
/// declared `form` means form, and a client that declared only `url` cannot
/// render the question this module asks.
///
/// A function rather than an expression inside [`Confirm::to`] so the tests
/// exercise the predicate that actually decides, instead of a second copy of
/// it that agrees today.
#[must_use]
pub fn can_answer_a_form(capabilities: &rmcp::model::ClientCapabilities) -> bool {
    capabilities.elicitation.as_ref().is_some_and(|e| {
        // A bare `elicitation: {}` means form. That capability existed before
        // the form/url split, so a client declaring it declares the original
        // flow -- and reading bare as "no form" would silently refuse to ask
        // every client that predates the split, falling back to the `dry_run`
        // convention while looking like elicitation was tried.
        //
        // URL-only is the case that must NOT be treated as form: such a client
        // declared what it can do, and it is not this. Sending it a form is
        // asking a question it cannot answer, on a destructive operation.
        e.form.is_some() || e.url.is_none()
    })
}

/// What came back from asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Nobody could be asked: the client declared no elicitation capability.
    ///
    /// Deliberately NOT a refusal. A client without the capability is the
    /// common case, and treating "there was nobody to ask" as "they said no"
    /// would make `shutdown_server` impossible on every stock client.
    Unavailable,
    /// A person was asked and said yes.
    Confirmed,
    /// A person was asked and the act must not happen, with the sentence to
    /// report. Covers a decline, a cancel, a form returning `false`, and a
    /// round trip that did not complete — every one of which means the same
    /// thing to the caller: nothing was done.
    Refused(String),
}

impl Answer {
    /// Whether the act may proceed.
    ///
    /// [`Answer::Unavailable`] proceeds because the tool's own opt-in — the
    /// `dry_run=false` the caller passed, or `--mcp-allow-open-capture` the
    /// operator set — is still the guard it was before this module existed.
    #[must_use]
    pub fn permits(&self) -> bool {
        matches!(self, Self::Unavailable | Self::Confirmed)
    }
}

/// Where one tool call's confirmation question goes, or nowhere.
///
/// Cloneable and cheap: a peer handle, not a buffer. Shaped after
/// [`super::progress::Progress`] on purpose — both are "a channel back to the
/// caller, or nothing", both are inserted into every tool call's extensions so
/// no handler has to ask whether it was given one, and both are silent rather
/// than failing when the client cannot receive.
#[derive(Clone)]
pub struct Confirm {
    /// The peer to ask, or `None` when the client cannot be asked.
    peer: Option<rmcp::Peer<RoleServer>>,
}

impl std::fmt::Debug for Confirm {
    /// Prints whether anyone can be asked, not the peer.
    ///
    /// `Peer` has no useful `Debug`, and the only question anyone debugging a
    /// confirmation that never appeared asks is whether the client declared
    /// the capability.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Confirm")
            .field("available", &self.available())
            .finish()
    }
}

impl Confirm {
    /// A confirmer with nobody on the other end.
    ///
    /// What a client that declared no elicitation capability gets, and what a
    /// test calling a handler directly passes in.
    #[must_use]
    pub fn unavailable() -> Self {
        Self { peer: None }
    }

    /// A confirmer for `peer`, if that peer said it can answer.
    ///
    /// [`can_answer_a_form`] decides. Reading the capability here rather than
    /// at each call site means a handler cannot forget to, and a request the
    /// client never advertised is never put on the wire.
    #[must_use]
    pub fn to(peer: rmcp::Peer<RoleServer>) -> Self {
        let reachable = peer
            .peer_info()
            .is_some_and(|info| can_answer_a_form(&info.capabilities));
        Self {
            peer: reachable.then_some(peer),
        }
    }

    /// Whether there is anyone to ask.
    #[must_use]
    pub fn available(&self) -> bool {
        self.peer.is_some()
    }

    /// Put one yes/no question to the person driving the client.
    ///
    /// `message` is what they read; `label` titles the single checkbox and
    /// `consequence` describes what saying yes does. All three are sipnab's own
    /// words — no captured text reaches this, for the reason
    /// [`super::sampling`] spells out at length about the other direction.
    ///
    /// # Why every failure is a refusal
    ///
    /// A transport that dropped, a client that answered with the wrong result
    /// type, and an action this build does not recognize all mean sipnab did
    /// not obtain a yes. The act is irreversible, so the only safe reading of
    /// "no answer" is "no". [`Answer::Unavailable`] is the one case that is not
    /// a failure, and it is decided before anything is sent.
    pub async fn ask(&self, message: &str, label: &str, consequence: &str) -> Answer {
        let Some(peer) = &self.peer else {
            return Answer::Unavailable;
        };
        let schema = match ElicitationSchema::builder()
            .required_bool_with(CONFIRM_FIELD, |b| {
                b.title(label.to_string())
                    .description(consequence.to_string())
            })
            .build()
        {
            Ok(schema) => schema,
            Err(e) => {
                return Answer::Refused(format!(
                    "sipnab could not build the confirmation form ({e}); nothing was done"
                ));
            }
        };
        let params = ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: message.to_string(),
            requested_schema: schema,
        };
        let reply = match peer
            .send_request(ServerRequest::ElicitRequest(ElicitRequest::new(params)))
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                return Answer::Refused(format!(
                    "the confirmation was not answered ({e}); nothing was done"
                ));
            }
        };
        let ClientResult::ElicitResult(result) = reply else {
            return Answer::Refused(
                "the client answered the confirmation with something other than an \
                 elicitation result; nothing was done"
                    .to_string(),
            );
        };
        match result.action {
            ElicitationAction::Accept => {
                let said_yes = result
                    .content
                    .as_ref()
                    .and_then(|c| c.get(CONFIRM_FIELD))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                if said_yes {
                    Answer::Confirmed
                } else {
                    // An accepted form is not a yes. A client that renders the
                    // checkbox unticked and lets the user submit sends
                    // `accept` with `confirm: false`, and reading the action
                    // alone would stop the server on a form the person
                    // deliberately left empty.
                    Answer::Refused(format!(
                        "the confirmation came back with {CONFIRM_FIELD}=false; nothing was done"
                    ))
                }
            }
            ElicitationAction::Decline => {
                Answer::Refused("the confirmation was declined; nothing was done".to_string())
            }
            ElicitationAction::Cancel => {
                Answer::Refused("the confirmation was canceled; nothing was done".to_string())
            }
            // `ElicitationAction` is `#[non_exhaustive]`: a revision that adds
            // an action must not turn into an accidental yes here.
            _ => Answer::Refused(
                "the confirmation came back with an action this build does not \
                 recognize; nothing was done"
                    .to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{
        ClientCapabilities, ElicitationCapability, FormElicitationCapability,
        UrlElicitationCapability,
    };

    /// Client capabilities declaring `elicitation` as given.
    ///
    /// Built field by field because every capability type is
    /// `#[non_exhaustive]`: struct-expression syntax does not compile from
    /// outside rmcp, which is also why nothing in this repository may assume
    /// their shape.
    fn declaring(elicitation: Option<ElicitationCapability>) -> ClientCapabilities {
        let mut caps = ClientCapabilities::default();
        caps.elicitation = elicitation;
        caps
    }

    /// A client that said nothing about elicitation is never sent one.
    #[test]
    fn a_client_that_declared_nothing_cannot_be_asked() {
        assert!(!can_answer_a_form(&ClientCapabilities::default()));
    }

    /// A client that declared `form` can be asked.
    #[test]
    fn a_client_that_declared_form_can_be_asked() {
        let caps = declaring(Some(
            ElicitationCapability::new().with_form(FormElicitationCapability::new()),
        ));
        assert!(can_answer_a_form(&caps));
    }

    /// A bare `elicitation: {}` predates the form/url split and means form.
    ///
    /// The spec's own reading. Treating it as unaskable would silently drop
    /// every client written against the earlier revision back onto the
    /// convention, and nothing would report that it had happened.
    #[test]
    fn a_bare_elicitation_capability_means_form() {
        assert!(can_answer_a_form(&declaring(Some(
            ElicitationCapability::new()
        ))));
    }

    /// A client that can only open a URL cannot render this question.
    #[test]
    fn a_url_only_client_cannot_be_asked_a_form() {
        let caps = declaring(Some(
            ElicitationCapability::new().with_url(UrlElicitationCapability::new()),
        ));
        assert!(
            !can_answer_a_form(&caps),
            "a url-only client would be sent a form it cannot render"
        );
    }

    /// Nobody to ask is not a refusal.
    ///
    /// The distinction the whole fallback rests on: if `Unavailable` did not
    /// permit, `shutdown_server` would stop working on every client that never
    /// declared the capability.
    #[tokio::test]
    async fn nobody_to_ask_permits_and_says_so() {
        let confirm = Confirm::unavailable();
        assert!(!confirm.available());
        let answer = confirm.ask("stop?", "Stop", "ends the run").await;
        assert_eq!(answer, Answer::Unavailable);
        assert!(answer.permits());
    }

    /// A refusal does not permit, whatever produced it.
    #[test]
    fn a_refusal_never_permits() {
        assert!(!Answer::Refused("declined".to_string()).permits());
        assert!(Answer::Confirmed.permits());
    }

    /// The form asks for exactly the field the answer is read from.
    ///
    /// Two spellings of one name is the failure that would make every accepted
    /// confirmation read as a refusal, and it would look like a working tool
    /// that nobody could ever confirm.
    #[test]
    fn the_form_asks_for_the_field_the_answer_is_read_from() {
        let schema = ElicitationSchema::builder()
            .required_bool_with(CONFIRM_FIELD, |b| b.title("Confirm"))
            .build()
            .expect("the confirmation schema must build");
        assert!(
            schema.properties.contains_key(CONFIRM_FIELD),
            "the schema does not carry '{CONFIRM_FIELD}': {schema:?}"
        );
        assert_eq!(
            schema.required.as_deref(),
            Some([CONFIRM_FIELD.to_string()].as_slice()),
            "the confirmation must be required, or a client may omit it"
        );
    }

    /// The form serializes as MCP's `form` mode, with the message and schema.
    ///
    /// Proves the bytes rather than the builder call: this is the request a
    /// client has to recognize, and a `mode` the spec does not name is a
    /// request nothing answers.
    #[test]
    fn the_request_serializes_as_a_form_elicitation() {
        let params = ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: "Stop the sipnab server?".to_string(),
            requested_schema: ElicitationSchema::builder()
                .required_bool_with(CONFIRM_FIELD, |b| b.title("Confirm"))
                .build()
                .expect("schema"),
        };
        let wire = serde_json::to_value(&params).expect("the params must serialize");
        assert_eq!(wire["mode"], "form");
        assert_eq!(wire["message"], "Stop the sipnab server?");
        assert_eq!(wire["requestedSchema"]["type"], "object");
        assert_eq!(
            wire["requestedSchema"]["properties"][CONFIRM_FIELD]["type"],
            "boolean"
        );
        assert_eq!(
            wire["requestedSchema"]["required"][0], CONFIRM_FIELD,
            "the confirmation field must be required on the wire: {wire}"
        );
    }
}
