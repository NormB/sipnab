// SPDX-License-Identifier: MIT OR Apache-2.0

//! vCon containers: producing them, and checking them before somebody else
//! does.
//!
//! # Why these two live together
//!
//! They are one workflow. An agent handing containers to a conserver exports
//! a set, checks that the store will accept them, and records what it sent.
//! Splitting the export from the check across two files would put the
//! producer's half and the reader's half in different places, and the second
//! tool exists precisely because the first one had no way to answer "will this
//! be accepted".
//!
//! # What changed, and why the tool was not simply a smaller CLI
//!
//! `--export-vcon-when` takes the filter DSL and emits one container per
//! matching dialog; the tool took ONE `call_id`. An agent asked to export
//! every failed call had to list dialogs and then issue one call each — on a
//! real capture, hundreds of round trips to do what one CLI invocation does.
//! So the filter is here, bounded by `--mcp-max-rows` like every other
//! set-returning tool.
//!
//! `--vcon-digest` had no counterpart either, and its whole purpose — binding
//! an emission to a store's ledger entry out of band — is something an agent
//! needs more than a person does. Every container comes back with its SHA-256,
//! over the same bytes an export writes.
//!
//! # The omissions travel with the container
//!
//! A container whose audio was refused for size looks, to a reader, exactly
//! like a conversation that had no audio. The completeness carrier has always
//! said which of those happened — in prose, inside an attachment whose body is
//! a JSON string. That is a fine answer for a person and no answer at all for
//! a caller, so the response carries the caveat, the inline-media bound this
//! run enforced, and one row per omission.

use crate::mcp::server::SipnabMcp;
use crate::mcp::shape::resolve_limit_with_cap;
use rmcp::handler::server::tool::schema_for_output;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};

/// Parameters for `export_vcon`.
///
/// No `format`, unlike its neighbors. A vCon IS a JSON container defined by
/// `draft-ietf-vcon-vcon-core`, so a "markdown" arm would be a rendering of a
/// document whose whole purpose is to travel between machines — and offering
/// one invites an agent to ask for it and then hand the prose to something
/// expecting a container.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExportVconParams {
    /// Call-ID identifying the one dialog to export.
    ///
    /// Give this or `filter`, never both — the CLI refuses the same pair for
    /// the same reason: a request naming a dialog AND a rule for choosing
    /// dialogs has two answers and no way to say which was meant.
    pub call_id: Option<String>,
    /// Filter selecting the dialogs to export — a named alias or a raw DSL
    /// expression, the vocabulary `list_dialogs` and `--export-vcon-when`
    /// take.
    pub filter: Option<String>,
    /// Maximum containers to return (default 50, ceiling `--mcp-max-rows`, itself 1000 unless the operator says otherwise).
    ///
    /// A container is a large answer, so a filter matching a whole capture is
    /// bounded here rather than in the caller's memory. `total_matched` says
    /// how many there were.
    pub limit: Option<u32>,
}

/// Parameters for `validate_vcon`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ValidateVconParams {
    /// Call-ID of a dialog to export and then validate.
    ///
    /// Give this or `container`, never both.
    pub call_id: Option<String>,
    /// A container to validate, supplied by the caller.
    ///
    /// Anything at all: one sipnab exported earlier, one another producer
    /// wrote, one a store rejected. The schema does not care where it came
    /// from, and neither does this.
    pub container: Option<serde_json::Value>,
}

/// One thing a container does not carry, as a row.
///
/// The wire shape of [`crate::output::vcon::Omission`]. It is spelled again
/// here rather than re-exported because the exporter lives behind the `vcon`
/// Cargo feature and this response type must exist on every build that carries
/// the MCP server. `an_omission_row_is_the_wire_shape_of_the_carriers_row`
/// gates the two against each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct OmissionRow {
    /// Stable machine identifier — the carrier field this row was read from.
    pub kind: String,
    /// How many times it happened; `1` for a fact that either happened or did
    /// not.
    pub count: u64,
    /// What one occurrence is — `frame`, `message`, `dialog`, `header`, `run`,
    /// `recording`, `blind-spot`.
    pub unit: String,
}

/// What this container does not contain, and why.
///
/// RV7. The same facts the container carries in its completeness attachment,
/// in the tool's OWN response — because the attachment's body is a JSON string
/// per §2.3, and an agent that has to parse a document out of a document to
/// learn that the audio was refused will not do it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ContainerCompleteness {
    /// The prose caveat, verbatim from the container.
    pub note: String,
    /// What became of this dialog's audio: `carried`, `refused-over-budget`,
    /// `none-decodable` or `not-considered`.
    pub media: String,
    /// The audio's own provenance note, when there is audio to describe or a
    /// refusal to explain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_note: Option<String>,
    /// The inline-media budget this export ENFORCED, in bytes of base64url.
    ///
    /// The number that was applied, never the compiled-in default: an operator
    /// who set `--vcon-max-inline-media` and reads the default here goes
    /// looking for a limit nothing enforced.
    pub max_inline_media_bytes: usize,
    /// Whether this container omits nothing at all.
    pub complete: bool,
    /// One row per omission, empty when there are none.
    pub omissions: Vec<OmissionRow>,
}

/// One container, with what identifies it and what it lacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExportedContainer {
    /// The dialog this container describes.
    pub call_id: String,
    /// SHA-256 of the container, lowercase hex.
    ///
    /// Computed the way `--vcon-digest` computes one — the same function, over
    /// the container's own serialized bytes — so a ledger entry a store
    /// recorded for a container it accepted can be compared against this
    /// without either side knowing how the other spelled it.
    ///
    /// It identifies the DOCUMENT rather than the dialog. `created_at` is the
    /// moment sipnab wrote the container, so two exports of one call are two
    /// documents with two digests and one `uuid`; a consumer deduplicates on
    /// the uuid.
    pub digest: String,
    /// The container itself, as an object rather than as a string to re-parse.
    pub container: serde_json::Value,
    /// What this container does not contain.
    pub completeness: ContainerCompleteness,
}

/// The answer `export_vcon` gives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExportVconResponse {
    /// Version of this envelope.
    pub schema_version: u32,
    /// The containers, in store order.
    pub containers: Vec<ExportedContainer>,
    /// How many are in this response.
    pub returned: usize,
    /// How many dialogs the request selected, across the whole store.
    pub total_matched: usize,
    /// Whether `limit` cut the answer short.
    pub truncated: bool,
    /// Which capture this answer came from, and which revision of its stores.
    pub capture_identity: crate::provenance::CaptureEtag,
}

/// One place a container disagrees with the schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ValidationFinding {
    /// JSON Pointer to the offending value, `/dialog/2` shaped.
    pub instance_path: String,
    /// The schema keyword that refused it.
    pub keyword: String,
    /// What was wrong, in one sentence.
    pub detail: String,
    /// The documented deviation this finding IS, when it is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deviation: Option<String>,
}

/// Why a deviation is a deviation rather than a defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DeviationExplanation {
    /// The name the findings reference.
    pub name: String,
    /// What it is, and why sipnab emits it anyway.
    pub explanation: String,
}

/// The answer `validate_vcon` gives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ValidateVconResponse {
    /// Version of this envelope.
    pub schema_version: u32,
    /// `valid`, `valid-except-documented-deviation`, or `invalid`.
    ///
    /// Three answers rather than two. The middle one is the whole point: a
    /// validator that folded the shape the working group agreed into a clean
    /// bill would teach a producer that a missing `start` is fine.
    pub verdict: String,
    /// Where the schema this was checked against lives in the sipnab
    /// repository.
    pub schema_path: String,
    /// The `$id` that schema declares.
    pub schema_id: String,
    /// Findings that are NOT documented deviations. Empty on a clean pass.
    pub errors: Vec<ValidationFinding>,
    /// Findings that ARE documented deviations, kept apart from the errors.
    pub deviations: Vec<ValidationFinding>,
    /// One paragraph per distinct deviation named above.
    pub explanations: Vec<DeviationExplanation>,
    /// The dialog whose freshly exported container was validated, when the
    /// caller named one rather than supplying a document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
}

/// Which dialogs an export was asked for.
///
/// A caller that sent both `call_id` and `filter` has a malformed request, and
/// the arguments are read before anything else, so the mistake they can fix is
/// the one they are told about.
enum Selection {
    /// One named dialog. A Call-ID the store does not hold is an error, not an
    /// empty answer.
    One(String),
    /// Every dialog a filter matches, which may legitimately be none.
    Matching(Box<crate::sip::dsl::FilterExpr>),
}

#[tool_router(router = vcon_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Export observed dialogs as vCon conversation containers.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when neither `call_id` nor `filter` is given,
    /// when both are, for an unknown `call_id`, for a `filter` that is neither
    /// a known alias nor parseable, and on a build without the `vcon` feature.
    #[tool(
        name = "export_vcon",
        description = "Exports observed dialogs as vCon containers \
                       (draft-ietf-vcon-vcon-core, syntax 0.4.0), structured \
                       JSON, each with its SHA-256 and with what the capture \
                       missed. Takes ONE call_id, or a DSL filter selecting a \
                       SET -- use the filter rather than looping call_id, and \
                       bound it with limit. These are OBSERVER vCons: sipnab \
                       watched packets go past a tap, so nothing is signed and \
                       no party carries an established name. Audio the run \
                       RETAINED travels inline as a recording Dialog Object, \
                       base64url with a sha512 content_hash and never a url; \
                       over a measured size budget it is refused out loud and \
                       the refusal appears in this response's completeness \
                       block, alongside the applied bound and one row per \
                       omission. Returns an error when a named Call-ID is not \
                       in the active store, when call_id and filter are both \
                       given, or when this binary was built without the \
                       'vcon' feature.",
        output_schema = schema_for_output::<ExportVconResponse>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn export_vcon(
        &self,
        Parameters(params): Parameters<ExportVconParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let selection = self.vcon_selection(params.call_id, params.filter)?;
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        let response = self.export_containers(&selection, limit)?;

        // `ContentBlock::json` of the SERIALIZED response, never a rendered
        // string handed back for the caller to parse. `get_capture_report`
        // shipped the second shape: it asked a renderer with no JSON arm for
        // JSON, failed to parse the prose that came back, and fell through to
        // a text block -- so every agent that took the default format got
        // prose and nothing saying the structure it asked for was never there.
        let value = serde_json::to_value(&response).map_err(|e| {
            rmcp::ErrorData::internal_error(
                format!("vCon response serialization failed: {e}"),
                None,
            )
        })?;
        // A container carries `sip_display_name` and `sip_contact` verbatim:
        // whatever the sender wrote in its own headers. The note says so
        // rather than fencing the document, because fencing it would tell the
        // agent to distrust sipnab's own completeness caveat as well.
        Ok(CallToolResult::success(vec![
            ContentBlock::json(value)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }

    /// Check a container against the schema sipnab vendors.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when neither `call_id` nor `container` is
    /// given, when both are, for an unknown `call_id`, for a `container` that
    /// is not a JSON object, and on a build without the `vcon` feature.
    #[tool(
        name = "validate_vcon",
        description = "Validates a vCon container against the working group's \
                       schema as sipnab vendors it \
                       (tests/schemas/vcon.schema.json). Takes a call_id, \
                       whose container is exported and then checked, or a \
                       container supplied verbatim -- one sipnab wrote, or one \
                       another producer did. Answers valid, \
                       valid-except-documented-deviation, or invalid, and \
                       keeps the two kinds of finding apart: ordinary errors, \
                       and the ONE shape sipnab emits on purpose that the \
                       schema rejects -- the empty Dialog Object the working \
                       group agreed at IETF 124, which the draft's own \
                       Appendix B schema forbids because every Dialog Object \
                       requires a start. That deviation is reported by name \
                       with its reasoning, never folded into a clean pass. \
                       Use it before handing containers to a conserver: a \
                       store that refuses one tells whoever POSTed it, not \
                       whoever built it.",
        output_schema = schema_for_output::<ValidateVconResponse>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn validate_vcon(
        &self,
        Parameters(params): Parameters<ValidateVconParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let response = match (params.call_id, params.container) {
            (Some(_), Some(_)) => {
                return Err(rmcp::ErrorData::invalid_params(
                    "`call_id` and `container` are alternatives: the first \
                     exports a dialog and checks what it produced, the second \
                     checks a document you already hold. Give one",
                    None,
                ));
            }
            (None, None) => {
                return Err(rmcp::ErrorData::invalid_params(
                    "give `call_id` to export a dialog and validate it, or \
                     `container` to validate a document you already hold",
                    None,
                ));
            }
            (Some(call_id), None) => {
                let exported = self.export_containers(&Selection::One(call_id.clone()), 1)?;
                let container = exported
                    .containers
                    .first()
                    .map(|c| c.container.clone())
                    .ok_or_else(|| {
                        rmcp::ErrorData::internal_error(
                            format!("call_id '{call_id}' exported no container"),
                            None,
                        )
                    })?;
                let mut response = self.validate_container(&container)?;
                response.call_id = Some(call_id);
                response
            }
            (None, Some(container)) => {
                if !container.is_object() {
                    return Err(rmcp::ErrorData::invalid_params(
                        "a vCon container is a JSON object; this is not one, so \
                         there is nothing to validate. Pass the container \
                         itself, not a string holding it",
                        None,
                    ));
                }
                self.validate_container(&container)?
            }
        };

        let value = serde_json::to_value(&response).map_err(|e| {
            rmcp::ErrorData::internal_error(
                format!("validation response serialization failed: {e}"),
                None,
            )
        })?;
        Ok(CallToolResult::success(vec![ContentBlock::json(value)?]))
    }
}

impl SipnabMcp {
    /// Read the caller's `call_id`/`filter` pair into one selection.
    ///
    /// The refusals are the CLI's, deliberately: `--export-vcon` and
    /// `--export-vcon-when` conflict there too, and an agent that learned one
    /// surface should not find the other accepting a request it cannot answer.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when both are given, when neither is, or when
    /// the filter is neither a known alias nor parseable.
    fn vcon_selection(
        &self,
        call_id: Option<String>,
        filter: Option<String>,
    ) -> Result<Selection, rmcp::ErrorData> {
        match (call_id, filter) {
            (Some(_), Some(_)) => Err(rmcp::ErrorData::invalid_params(
                "`call_id` and `filter` are alternatives, not a pair: one names \
                 a dialog, the other names a rule for choosing them. Give one",
                None,
            )),
            (None, None) => Err(rmcp::ErrorData::invalid_params(
                "give `call_id` for one dialog, or `filter` for every dialog it \
                 selects -- for example \"response_code >= 400\"",
                None,
            )),
            (Some(id), None) => Ok(Selection::One(id)),
            (None, Some(expression)) => {
                let compiled = self.compile_filter(Some(&expression))?.ok_or_else(|| {
                    rmcp::ErrorData::invalid_params(
                        "an empty filter selects nothing and names nothing; omit \
                         it, or give an expression",
                        None,
                    )
                })?;
                Ok(Selection::Matching(Box::new(compiled)))
            }
        }
    }

    /// Build the containers a selection asks for.
    ///
    /// ONE pass over the store under ONE set of locks, with the capture facts
    /// and the analysis computed once for the whole answer. Per-container
    /// analysis would be quadratic — the analysis reads the whole store — and,
    /// worse, would let two containers in one response quote different
    /// numbers for the same run, which reads as two captures.
    ///
    /// The analysis is run rather than skipped, so each container's blind-spot
    /// list means "somebody looked" instead of "nobody looked" — two answers
    /// `CaptureCompleteness` deliberately keeps apart. It is unfiltered for
    /// the reason [`crate::analysis::analyze`] gives: an undecodable frame
    /// belongs to no dialog.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when a NAMED Call-ID is not in the store. A
    /// filter that matches nothing is an empty answer instead, because "no
    /// call failed" is a finding and "that call is not here" is a mistake.
    #[cfg(feature = "vcon")]
    fn export_containers(
        &self,
        selection: &Selection,
        limit: usize,
    ) -> Result<ExportVconResponse, rmcp::ErrorData> {
        use crate::output::vcon::{
            ExportContext, ObservedAudio, container_digest, export_dialog_and_completeness, seal,
            sealed_json,
        };

        let budget = self.max_inline_media_bytes;
        // Capture, dialogs, streams -- the order `CaptureState` documents. The
        // containers and the identity stamped beside them must describe one
        // store revision.
        let state = self.capture.read();
        let ds = self.dialog_store.read();
        let ss = self.stream_store.read();
        let capture_identity = state.identity.etag(ds.generation(), ss.generation());

        let facts =
            crate::analysis::CaptureFacts::observed(&ds, &ss, crate::capture::captured_packets());
        let analysis = crate::analysis::analyze_with(&ds, &ss, None, &facts);
        let capture = crate::rtp::diagnosis::CaptureMedia::of_store(&ss);
        let delay = crate::rtp::quality::MosDelay::from_capture(&ss);

        let mut containers = Vec::new();
        let mut total_matched = 0_usize;
        for dialog in ds.iter() {
            let streams: Vec<&crate::rtp::stream::RtpStream> =
                ss.streams_for(&dialog.call_id).collect();
            let selected = match selection {
                Selection::One(id) => dialog.call_id == *id,
                Selection::Matching(expr) => expr.matches_dialog(dialog, &streams, capture, delay),
            };
            if !selected {
                continue;
            }
            total_matched += 1;
            if containers.len() >= limit {
                // Counted, not built. `total_matched` is the number an agent
                // pages against, and it cannot be known from a scan that
                // stopped at the limit.
                continue;
            }

            // Media is attempted always. When the run retained no payload the
            // decode fails, and its message -- which reports what was MEASURED
            // and never claims the call was silent -- travels in the container
            // instead of an absence the agent would have to interpret.
            let decoded = crate::rtp::audio_export::decode_dialog_audio(&streams);
            let reason = decoded
                .as_ref()
                .err()
                .map_or_else(String::new, ToString::to_string);
            let audio = match decoded.as_ref() {
                Ok(audio) => ObservedAudio::Decoded(audio),
                Err(_) => ObservedAudio::NothingToDecode(&reason),
            };

            let context = ExportContext {
                capture_id: crate::output::vcon::dialog_capture_id(dialog),
                facts: &facts,
                analysis: Some(&analysis),
                max_inline_media_bytes: budget,
            };
            let exported =
                export_dialog_and_completeness(dialog, &context, audio, chrono::Utc::now());

            // The digest is over the bytes an export WRITES, so it joins to a
            // `--vcon-digest` line and to a store's ledger entry. Taking it
            // over `to_value`'s output instead would produce a number that
            // matches nothing outside this process.
            let text = sealed_json(&seal(exported.container, None)).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("vCon serialization failed: {e}"), None)
            })?;
            let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
                rmcp::ErrorData::internal_error(
                    format!("vCon serialization is not readable JSON: {e}"),
                    None,
                )
            })?;

            containers.push(ExportedContainer {
                call_id: dialog.call_id.clone(),
                digest: container_digest(text.as_bytes()),
                container: value,
                completeness: completeness_rows(&exported.completeness, context.media_budget()),
            });
        }
        drop(ss);
        drop(ds);
        drop(state);

        if let Selection::One(id) = selection
            && total_matched == 0
        {
            return Err(rmcp::ErrorData::invalid_params(
                format!("call_id '{id}' not found"),
                None,
            ));
        }

        Ok(ExportVconResponse {
            schema_version: 1,
            returned: containers.len(),
            truncated: total_matched > containers.len(),
            containers,
            total_matched,
            capture_identity,
        })
    }

    /// Validate one container against the vendored schema.
    ///
    /// # Errors
    ///
    /// Never on a build carrying the exporter: a container that disagrees with
    /// the schema is an ANSWER, not a tool error. An agent that got `-32602`
    /// for an invalid document would have to distinguish "your container is
    /// wrong" from "your request was wrong", and only one of those is
    /// something it can fix by editing the container.
    #[cfg(feature = "vcon")]
    fn validate_container(
        &self,
        container: &serde_json::Value,
    ) -> Result<ValidateVconResponse, rmcp::ErrorData> {
        let report = crate::output::vcon_schema::validate(container);
        Ok(ValidateVconResponse {
            schema_version: 1,
            verdict: report.verdict.as_str().to_owned(),
            schema_path: report.schema_path.to_owned(),
            schema_id: report.schema_id,
            errors: report.errors.iter().map(finding_row).collect(),
            deviations: report.deviations.iter().map(finding_row).collect(),
            explanations: report
                .explanations
                .iter()
                .map(|e| DeviationExplanation {
                    name: e.name.to_owned(),
                    explanation: e.explanation.to_owned(),
                })
                .collect(),
            call_id: None,
        })
    }
}

/// The completeness carrier, in the shape this response publishes it.
#[cfg(feature = "vcon")]
fn completeness_rows(
    completeness: &crate::output::vcon::CaptureCompleteness,
    budget: usize,
) -> ContainerCompleteness {
    ContainerCompleteness {
        note: completeness.note.clone(),
        media: completeness.media.as_str().to_owned(),
        media_note: completeness.media_note.clone(),
        max_inline_media_bytes: budget,
        complete: completeness.complete(),
        omissions: completeness
            .omissions()
            .iter()
            .map(|o| OmissionRow {
                kind: o.kind.to_owned(),
                count: o.count,
                unit: o.unit.to_owned(),
            })
            .collect(),
    }
}

/// One schema finding, in the shape this response publishes it.
#[cfg(feature = "vcon")]
fn finding_row(finding: &crate::output::vcon_schema::SchemaFinding) -> ValidationFinding {
    ValidationFinding {
        instance_path: finding.instance_path.clone(),
        keyword: finding.keyword.to_owned(),
        detail: finding.detail.clone(),
        deviation: finding.deviation.map(str::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    use parking_lot::RwLock;
    use std::sync::Arc;

    /// One instant every fixture shares, so a uuid's timestamp half can never
    /// be what tells two dialogs apart.
    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0)
            .single()
            .expect("a real instant")
    }

    /// Parse `raw` as SIP between localhost endpoints.
    fn parse_at(raw: &[u8]) -> crate::sip::SipMessage {
        let local = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        crate::sip::parser::parse_sip(
            raw,
            ts(),
            local,
            local,
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("fixture parses as SIP")
    }

    /// A minimal well-formed INVITE for `call_id`.
    fn invite(call_id: &str) -> crate::sip::SipMessage {
        parse_at(&crate::test_utils::build_sip_message(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "User-Agent: TestUA/1.0",
                "Content-Length: 0",
            ],
            b"",
        ))
    }

    /// The matching final response for `call_id`.
    fn final_response(call_id: &str, code: u16, reason: &str) -> crate::sip::SipMessage {
        parse_at(&crate::test_utils::build_sip_message(
            &format!("SIP/2.0 {code} {reason}"),
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                // RFC 3261 §12.1.1: a 2xx to INVITE is the dialog's remote
                // target. Without it this fixture is not the conformant call
                // it claims to be.
                "Contact: <sip:bob@127.0.0.1>",
                "Content-Length: 0",
            ],
            b"",
        ))
    }

    /// A server over empty stores.
    fn empty_server() -> SipnabMcp {
        SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(100, false))),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
    }

    /// A server holding one dialog per `(call_id, final status)` pair.
    fn server_with(calls: &[(&str, u16)]) -> SipnabMcp {
        let mut ds = DialogStore::new(100, false);
        for (call_id, code) in calls {
            ds.process_message(invite(call_id));
            ds.process_message(final_response(call_id, *code, "Fixture"));
        }
        SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
    }

    /// The payload block of a result, skipping the untrusted-content note.
    ///
    /// Only a build carrying the exporter ever gets a payload; the other one
    /// gets a refusal, which is a message rather than a document.
    #[cfg(feature = "vcon")]
    fn payload(result: &CallToolResult) -> serde_json::Value {
        let note = crate::mcp::shape::untrusted_note();
        let text = result
            .content
            .iter()
            .filter_map(rmcp::model::ContentBlock::as_text)
            .map(|t| t.text.clone())
            .find(|t| *t != note)
            .expect("a payload block that is not the note");
        serde_json::from_str(&text).expect("the payload is JSON")
    }

    /// The JSON-RPC code of a refusal.
    fn code_of(err: rmcp::ErrorData) -> i64 {
        serde_json::to_value(err)
            .ok()
            .and_then(|v| v["code"].as_i64())
            .unwrap_or_default()
    }

    /// The text of a refusal.
    fn message_of(err: rmcp::ErrorData) -> String {
        serde_json::to_value(err)
            .ok()
            .and_then(|v| v["message"].as_str().map(str::to_string))
            .unwrap_or_default()
    }

    /// An `export_vcon` answer, parsed.
    ///
    /// Goes through the CONTENT BLOCK rather than calling the builder, so a
    /// handler that rendered the response to a string and handed back prose
    /// fails here instead of being papered over by a direct call.
    #[cfg(feature = "vcon")]
    async fn exported(server: &SipnabMcp, params: ExportVconParams) -> serde_json::Value {
        let result = server
            .export_vcon(Parameters(params))
            .await
            .expect("the export should succeed");
        payload(&result)
    }

    // ── export_vcon: the single-dialog form ──────────────────────────

    /// A known Call-ID answers with a structured container describing it.
    ///
    /// `is_object` is load-bearing, not decoration. A handler that serialized
    /// the container to a string and wrapped THAT parses back to a JSON
    /// *string*, and a handler that rendered prose does not parse at all --
    /// `get_capture_report` shipped the second shape and returned prose under
    /// its own default format for a release.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn export_vcon_returns_a_structured_container_for_a_known_call() {
        let server = server_with(&[("vcon-ok@x", 200)]);
        let v = exported(
            &server,
            ExportVconParams {
                call_id: Some("vcon-ok@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await;

        assert_eq!(v["returned"], 1, "one dialog, one container: {v}");
        assert_eq!(v["total_matched"], 1, "{v}");
        assert_eq!(v["truncated"], false, "{v}");

        let container = &v["containers"][0]["container"];
        assert!(
            container.is_object(),
            "the container must be an object, not a stringified blob or a \
             rendered report: {container}"
        );
        assert_eq!(
            container["vcon"],
            crate::output::vcon::VCON_SYNTAX_VERSION,
            "the container must state the syntax version a consumer parses \
             against"
        );
        assert_eq!(
            container["dialog"][0]["sip_call_id"], "vcon-ok@x",
            "the container names a different dialog than the one asked for"
        );
        assert_eq!(v["containers"][0]["call_id"], "vcon-ok@x", "{v}");

        let parties = container["parties"]
            .as_array()
            .expect("parties is an array");
        assert_eq!(
            parties.len(),
            3,
            "expected the two observed parties plus the sipnab observer, got {}",
            parties.len()
        );
        assert_eq!(
            parties[2]["role"], "observer",
            "the last party must be the sipnab observer, or every attachment's \
             `party` index points at a caller"
        );
        for party in parties {
            // A `name` IS emitted. What stops it reading as an established
            // identity is `validation: "none"` traveling beside it, so the
            // pairing is the invariant rather than the absence.
            assert_eq!(
                party["validation"], "none",
                "a party names somebody without saying sipnab established \
                 nothing: {party}"
            );
        }
    }

    /// Two different dialogs answer with two different containers.
    ///
    /// Without this a handler returning one constant satisfies every other
    /// assertion here.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn export_vcon_discriminates_between_two_dialogs() {
        let server = server_with(&[("vcon-a@x", 200), ("vcon-b@x", 200)]);
        let a = exported(
            &server,
            ExportVconParams {
                call_id: Some("vcon-a@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await;
        let b = exported(
            &server,
            ExportVconParams {
                call_id: Some("vcon-b@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await;

        assert_eq!(
            a["containers"][0]["container"]["dialog"][0]["sip_call_id"],
            "vcon-a@x"
        );
        assert_eq!(
            b["containers"][0]["container"]["dialog"][0]["sip_call_id"],
            "vcon-b@x"
        );
        assert_ne!(
            a["containers"][0]["container"]["uuid"], b["containers"][0]["container"]["uuid"],
            "two conversations share one vCon uuid, so a consumer \
             deduplicating on it keeps one and discards the other. These two \
             dialogs share a `created_at` deliberately -- the uuid's timestamp \
             half cannot tell them apart, and only the Call-ID seed can"
        );
        assert_ne!(
            a["containers"][0]["digest"], b["containers"][0]["digest"],
            "two containers describing different calls must not share a \
             digest, or the value identifies nothing"
        );
    }

    /// Re-exporting one dialog keeps its identifier AND its digest.
    ///
    /// The assertion that discriminates, and the opposite of the one above: an
    /// exporter minting a fresh uuid per call passes
    /// `export_vcon_discriminates_between_two_dialogs` and breaks every
    /// consumer that deduplicates on the identifier.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn export_vcon_is_stable_across_calls_for_one_dialog() {
        let server = server_with(&[("vcon-stable@x", 200)]);
        let params = || ExportVconParams {
            call_id: Some("vcon-stable@x".to_string()),
            ..ExportVconParams::default()
        };
        let first = exported(&server, params()).await;
        let second = exported(&server, params()).await;
        assert_eq!(
            first["containers"][0]["container"]["uuid"],
            second["containers"][0]["container"]["uuid"],
            "two exports of one dialog minted two identifiers"
        );

        // The digest is a function of the BYTES, and the bytes carry
        // `created_at` -- the moment the container was written, not a fact
        // about the call. So two exports of one dialog are two documents, and
        // the digest binds ONE emission to a ledger entry. The uuid above is
        // what a consumer deduplicates on; a reader who reached for the digest
        // instead would keep every re-export.
        //
        // Stated as a total rule rather than as one branch, so it holds
        // whichever way the clock falls between the two calls.
        let (a, b) = (&first["containers"][0], &second["containers"][0]);
        if a["container"]["created_at"] == b["container"]["created_at"] {
            assert_eq!(
                a["digest"], b["digest"],
                "identical bytes must hash identically"
            );
        } else {
            assert_ne!(
                a["digest"], b["digest"],
                "two documents that differ must not share a digest"
            );
        }
    }

    /// A digest is a SHA-256, spelled the way `sha256sum` spells one.
    ///
    /// The format is the interoperation. A digest an operator cannot paste
    /// beside a `--vcon-digest` line joins to nothing.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_digest_is_lowercase_hex_sha256() {
        let v = exported(
            &server_with(&[("vcon-hex@x", 200)]),
            ExportVconParams {
                call_id: Some("vcon-hex@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await;
        let digest = v["containers"][0]["digest"]
            .as_str()
            .expect("a digest string");
        assert_eq!(digest.len(), 64, "SHA-256 is 32 bytes of hex: {digest}");
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "lowercase hex, the spelling `sha256sum` writes: {digest}"
        );
    }

    /// An unknown Call-ID errors with invalid_params (-32602).
    ///
    /// Not `internal_error`, and emphatically not an empty success: an agent
    /// handed an empty list reads it as a capture that held no such call and
    /// moves on.
    #[tokio::test]
    async fn export_vcon_unknown_call_id_errors() {
        let err = empty_server()
            .export_vcon(Parameters(ExportVconParams {
                call_id: Some("nonexistent@nowhere".to_string()),
                ..ExportVconParams::default()
            }))
            .await
            .expect_err("unknown call_id must error");
        assert_eq!(code_of(err), -32602);
    }

    /// A request naming neither a dialog nor a rule is refused.
    #[tokio::test]
    async fn export_vcon_refuses_a_request_that_selects_nothing() {
        let err = empty_server()
            .export_vcon(Parameters(ExportVconParams::default()))
            .await
            .expect_err("a request selecting nothing must be refused");
        let message = message_of(err);
        assert!(
            message.contains("call_id") && message.contains("filter"),
            "the refusal must name both ways to select: {message}"
        );
    }

    /// A request naming both is refused, as the CLI refuses the same pair.
    #[tokio::test]
    async fn export_vcon_refuses_a_call_id_and_a_filter_together() {
        let err = empty_server()
            .export_vcon(Parameters(ExportVconParams {
                call_id: Some("a@x".to_string()),
                filter: Some("response_code >= 400".to_string()),
                limit: None,
            }))
            .await
            .expect_err("two selections must be refused");
        let json = serde_json::to_value(err).expect("the error serializes");
        assert_eq!(json["code"], -32602);
        assert!(
            json["message"]
                .as_str()
                .unwrap_or_default()
                .contains("alternatives"),
            "the refusal must say the two are alternatives rather than \
             silently preferring one: {json}"
        );
    }

    /// An unparseable filter is refused by name.
    #[tokio::test]
    async fn export_vcon_refuses_an_unparseable_filter() {
        let err = empty_server()
            .export_vcon(Parameters(ExportVconParams {
                filter: Some("response_code >>> 400".to_string()),
                ..ExportVconParams::default()
            }))
            .await
            .expect_err("a broken filter must be refused");
        assert_eq!(code_of(err), -32602);
    }

    // ── export_vcon: the filter form (RV5) ───────────────────────────

    /// RV5: one call exports every dialog a filter selects.
    ///
    /// The whole point. An agent asked to export every failed call used to
    /// list dialogs and then issue one `export_vcon` per row -- hundreds of
    /// round trips on a real capture to do what one CLI invocation does.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_filter_exports_every_matching_dialog_in_one_call() {
        let server = server_with(&[
            ("ok@x", 200),
            ("busy@x", 486),
            ("gone@x", 404),
            ("fine@x", 200),
        ]);
        let v = exported(
            &server,
            ExportVconParams {
                filter: Some("response_code >= 400".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await;

        assert_eq!(v["total_matched"], 2, "two calls failed: {v}");
        assert_eq!(v["returned"], 2, "and both containers came back: {v}");
        assert_eq!(v["truncated"], false, "nothing was cut: {v}");

        let mut ids: Vec<&str> = v["containers"]
            .as_array()
            .expect("containers is an array")
            .iter()
            .map(|c| c["call_id"].as_str().unwrap_or_default())
            .collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            vec!["busy@x", "gone@x"],
            "the filter must select the failures and only the failures: {v}"
        );
    }

    /// RV5: the answer is bounded, and says it was.
    ///
    /// A container is a large answer and a filter can select a whole capture.
    /// `total_matched` is what an agent pages against, so it has to be the
    /// count across the STORE rather than the length of the list it got.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_filter_is_bounded_and_reports_what_it_left_behind() {
        let server = server_with(&[("a@x", 486), ("b@x", 486), ("c@x", 486)]);
        let v = exported(
            &server,
            ExportVconParams {
                filter: Some("response_code >= 400".to_string()),
                limit: Some(1),
                ..ExportVconParams::default()
            },
        )
        .await;

        assert_eq!(v["returned"], 1, "the bound was applied: {v}");
        assert_eq!(
            v["containers"].as_array().map(Vec::len),
            Some(1),
            "`returned` must agree with the array it counts: {v}"
        );
        assert_eq!(
            v["total_matched"], 3,
            "the count is across the store, not across the page: {v}"
        );
        assert_eq!(v["truncated"], true, "and the caller is told: {v}");
    }

    /// A filter matching nothing is an empty answer, not an error.
    ///
    /// "No call failed" is a FINDING. Refusing it the way an unknown Call-ID
    /// is refused would make a clean capture look like a broken request.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_filter_that_matches_nothing_answers_with_an_empty_set() {
        let v = exported(
            &server_with(&[("ok@x", 200)]),
            ExportVconParams {
                filter: Some("response_code >= 400".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await;
        assert_eq!(v["total_matched"], 0, "{v}");
        assert_eq!(v["returned"], 0, "{v}");
        assert_eq!(v["truncated"], false, "nothing was withheld: {v}");
        assert!(
            v["containers"].as_array().is_some_and(Vec::is_empty),
            "an empty set is an empty array, not a missing key: {v}"
        );
    }

    // ── the omissions reach the caller (RV7) ─────────────────────────

    /// RV7: the caveat in the response is the caveat in the container.
    ///
    /// Not a second sentence written beside it. The container already carries
    /// the completeness note, inside an attachment whose body is JSON TEXT per
    /// §2.3 -- so an agent would have to parse a document out of a document to
    /// read it. This is the SAME string, lifted, and the assertion is that it
    /// is the same one rather than a paraphrase that can drift.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn the_response_carries_the_containers_own_caveat() {
        let v = exported(
            &server_with(&[("caveat@x", 200)]),
            ExportVconParams {
                call_id: Some("caveat@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await;
        let entry = &v["containers"][0];

        let inside: serde_json::Value = serde_json::from_str(
            entry["container"]["analysis"][0]["body"]
                .as_str()
                .expect("the analysis body is JSON text"),
        )
        .expect("the analysis body parses");
        let in_container = inside["capture_completeness"]["note"]
            .as_str()
            .expect("the container carries a note");

        assert_eq!(
            entry["completeness"]["note"].as_str(),
            Some(in_container),
            "the response's caveat and the container's must be one string: {entry}"
        );
        assert!(
            !in_container.is_empty(),
            "premise: there must be a caveat to carry"
        );
    }

    /// RV7: the applied inline-media bound is stated, not the compiled default.
    ///
    /// An operator who set `--vcon-max-inline-media` and reads the default
    /// here goes looking for a limit nothing enforced. The pair of assertions
    /// is what makes it a measurement: the default appears when nothing was
    /// set, and the setting appears when something was.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn the_response_states_the_inline_media_bound_it_enforced() {
        let params = || ExportVconParams {
            call_id: Some("bound@x".to_string()),
            ..ExportVconParams::default()
        };

        let unset = exported(&server_with(&[("bound@x", 200)]), params()).await;
        assert_eq!(
            unset["containers"][0]["completeness"]["max_inline_media_bytes"]
                .as_u64()
                .map(usize::try_from),
            Some(Ok(crate::output::vcon::MAX_INLINE_MEDIA_BYTES)),
            "with nothing set, the measured default is what was enforced: {unset}"
        );

        let tightened = server_with(&[("bound@x", 200)]).with_max_inline_media_bytes(Some(4096));
        let set = exported(&tightened, params()).await;
        assert_eq!(
            set["containers"][0]["completeness"]["max_inline_media_bytes"], 4096,
            "the number that was APPLIED, never the compiled-in one: {set}"
        );
    }

    /// RV7: the response says which media case applies, and `complete` never
    /// disagrees with the rows.
    ///
    /// The emptiness of the list on a genuinely clean capture is asserted in
    /// `output::vcon`, against a `CaptureFacts` the test constructs. It cannot
    /// be asserted HERE: `CaptureFacts::observed` reads process-global
    /// counters — undecodable frames, port-gate discards, oversize headers —
    /// that every other test in this binary shares, and `cargo test` runs them
    /// concurrently. A test asserting "no omissions" would pass or fail on
    /// which test won a race, which is a gate nobody could trust.
    ///
    /// What IS assertable here is the relationship, and it holds whatever the
    /// globals hold.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn the_response_states_the_media_case_and_keeps_complete_honest() {
        let v = exported(
            &server_with(&[("clean@x", 200)]),
            ExportVconParams {
                call_id: Some("clean@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await;
        let completeness = &v["containers"][0]["completeness"];
        let rows = completeness["omissions"]
            .as_array()
            .expect("an omissions array, present even when it is empty");

        assert_eq!(
            completeness["complete"],
            serde_json::json!(rows.is_empty()),
            "`complete` and the rows must be one answer: {completeness}"
        );
        assert_eq!(
            completeness["note"]
                .as_str()
                .unwrap_or_default()
                .matches("— INCOMPLETE:")
                .count(),
            rows.len(),
            "the prose and the rows must describe one set: {completeness}"
        );
        assert_eq!(
            completeness["media"], "none-decodable",
            "this run retained no payload for the dialog, which is a fact \
             about the RUN. An absent `media` key would read as a call with no \
             audio: {completeness}"
        );
        assert!(
            completeness["media_note"].is_string(),
            "and the reason travels with it: {completeness}"
        );
    }

    /// RV7: a retention loss becomes a row, and the row and the prose agree.
    ///
    /// The store is sized so it cannot hold what it is given, which is the one
    /// omission a unit test can produce without a capture: every other counter
    /// is a process-global the pipeline sets.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_retention_loss_reaches_the_response_as_a_row() {
        let mut ds = DialogStore::new(1, false);
        for id in ["first@x", "second@x"] {
            ds.process_message(invite(id));
            ds.process_message(final_response(id, 200, "Fixture"));
        }
        let server = SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(StreamStore::new(100))),
        );

        let v = exported(
            &server,
            ExportVconParams {
                filter: Some("state != 'Nothing'".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await;
        let completeness = &v["containers"][0]["completeness"];
        let rows = completeness["omissions"]
            .as_array()
            .expect("an omissions array");

        assert!(
            !rows.is_empty(),
            "a store that could not hold what it was given lost something, and \
             the response must say so: {completeness}"
        );
        assert!(
            rows.iter().any(|r| r["kind"]
                .as_str()
                .is_some_and(|k| k.starts_with("dialogs_"))),
            "the row must name the retention counter it came from: {completeness}"
        );
        assert_eq!(completeness["complete"], false, "{completeness}");

        let note = completeness["note"].as_str().unwrap_or_default();
        assert_eq!(
            note.matches("— INCOMPLETE:").count(),
            rows.len(),
            "the prose and the rows must describe one set: {completeness}"
        );
    }

    /// An omission row is the carrier's row, on the wire.
    ///
    /// The response type is spelled separately from
    /// [`crate::output::vcon::Omission`] because the exporter is behind a
    /// Cargo feature and this envelope is not. Two spellings of one fact is
    /// exactly the drift this repository keeps finding, so they are compared
    /// here rather than trusted.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_omission_row_is_the_wire_shape_of_the_carriers_row() {
        let carrier = crate::output::vcon::Omission {
            kind: "headers_dropped_oversize",
            count: 3,
            unit: "header",
        };
        let row = OmissionRow {
            kind: carrier.kind.to_owned(),
            count: carrier.count,
            unit: carrier.unit.to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&row).expect("serializes"),
            serde_json::to_value(&carrier).expect("serializes"),
            "the tool's row and the carrier's row must be one wire shape"
        );
    }

    // ── validate_vcon (RV6) ──────────────────────────────────────────

    /// A `validate_vcon` answer, parsed.
    #[cfg(feature = "vcon")]
    async fn validated(server: &SipnabMcp, params: ValidateVconParams) -> serde_json::Value {
        let result = server
            .validate_vcon(Parameters(params))
            .await
            .expect("validation should answer");
        payload(&result)
    }

    /// A container sipnab just exported passes the schema sipnab vendors.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn validate_vcon_passes_a_container_this_server_just_built() {
        let v = validated(
            &server_with(&[("valid@x", 200)]),
            ValidateVconParams {
                call_id: Some("valid@x".to_string()),
                ..ValidateVconParams::default()
            },
        )
        .await;

        assert_eq!(v["verdict"], "valid", "{v}");
        assert!(v["errors"].as_array().is_some_and(Vec::is_empty), "{v}");
        assert!(v["deviations"].as_array().is_some_and(Vec::is_empty), "{v}");
        assert_eq!(
            v["call_id"], "valid@x",
            "the answer must name what it judged: {v}"
        );
        assert_eq!(
            v["schema_path"], "tests/schemas/vcon.schema.json",
            "and which schema it read: {v}"
        );
    }

    /// RV6: a supplied container missing a required member is INVALID, and the
    /// finding says where.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn validate_vcon_refuses_a_dialog_object_with_no_start() {
        let v = validated(
            &empty_server(),
            ValidateVconParams {
                container: Some(serde_json::json!({
                    "uuid": "018f3a2b-4c5d-8e6f-9012-3456789abcde",
                    "created_at": "2026-09-01T12:00:00Z",
                    "dialog": [{"type": "transfer"}],
                })),
                ..ValidateVconParams::default()
            },
        )
        .await;

        assert_eq!(
            v["verdict"], "invalid",
            "a REFER that produced a transfer object with no `start` is the \
             defect a pass over 4,216 real containers found two of: {v}"
        );
        assert_eq!(v["errors"][0]["instance_path"], "/dialog/0", "{v}");
        assert_eq!(v["errors"][0]["keyword"], "required", "{v}");
        assert!(
            v["errors"][0]["detail"]
                .as_str()
                .is_some_and(|d| d.contains("start")),
            "the finding must name the member: {v}"
        );
        assert!(
            v["deviations"].as_array().is_some_and(Vec::is_empty),
            "nothing here is the documented deviation: {v}"
        );
    }

    /// RV6: the documented deviation is reported by name, with its reasoning.
    ///
    /// The verdict is neither `valid` nor `invalid`. A validator that answered
    /// `valid` here would teach a producer that a missing `start` is fine,
    /// which is the lesson the test above exists to refuse.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn validate_vcon_names_the_documented_deviation_rather_than_passing_it() {
        let v = validated(
            &empty_server(),
            ValidateVconParams {
                container: Some(serde_json::json!({
                    "uuid": "018f3a2b-4c5d-8e6f-9012-3456789abcde",
                    "created_at": "2026-09-01T12:00:00Z",
                    "dialog": [{}],
                })),
                ..ValidateVconParams::default()
            },
        )
        .await;

        assert_eq!(v["verdict"], "valid-except-documented-deviation", "{v}");
        assert!(
            v["errors"].as_array().is_some_and(Vec::is_empty),
            "the empty Dialog Object is not an ordinary error: {v}"
        );
        assert_eq!(v["deviations"][0]["instance_path"], "/dialog/0", "{v}");
        assert_eq!(
            v["deviations"][0]["deviation"], "empty-dialog-object",
            "{v}"
        );
        let explanation = v["explanations"][0]["explanation"]
            .as_str()
            .unwrap_or_default();
        assert!(
            explanation.contains("IETF 124") && explanation.contains("start"),
            "the reasoning has to travel with the finding, or a producer reads \
             a rejection with no way to tell whether it is theirs: {v}"
        );
    }

    /// Neither argument, and both arguments, are refused.
    #[tokio::test]
    async fn validate_vcon_refuses_a_request_naming_nothing_or_everything() {
        let neither = empty_server()
            .validate_vcon(Parameters(ValidateVconParams::default()))
            .await
            .expect_err("a request naming nothing must be refused");
        assert_eq!(code_of(neither), -32602);

        let both = empty_server()
            .validate_vcon(Parameters(ValidateVconParams {
                call_id: Some("a@x".to_string()),
                container: Some(serde_json::json!({})),
            }))
            .await
            .expect_err("a request naming both must be refused");
        assert_eq!(code_of(both), -32602);
    }

    /// A `container` that is not an object is refused, by name.
    ///
    /// The likely mistake is handing over the container as a STRING, which is
    /// what every surface here warns about in the other direction.
    #[tokio::test]
    async fn validate_vcon_refuses_a_container_that_is_not_an_object() {
        let err = empty_server()
            .validate_vcon(Parameters(ValidateVconParams {
                container: Some(serde_json::json!("{\"uuid\":\"x\"}")),
                ..ValidateVconParams::default()
            }))
            .await
            .expect_err("a string is not a container");
        assert_eq!(code_of(err), -32602);
    }
}
