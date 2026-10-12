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

use crate::mcp::errors::{self, Reason};
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
    /// Cursor: pass back the previous response's `next_cursor` verbatim
    /// (`<RFC 3339 created_at>|<Call-ID>`, the cursor `list_dialogs` uses).
    /// Omit on the first call.
    ///
    /// The position is only meaningful within one capture: compare
    /// `capture_identity.instance` between pages, as with every other paged
    /// tool.
    pub cursor: Option<String>,
    /// Whether retained audio travels inline: `inline` (the default) or
    /// `omit`.
    ///
    /// `omit` builds signaling-only containers. Each one records
    /// `media: "not-considered"` in its own completeness carrier, so a
    /// reader of the container learns that the export left the audio out,
    /// not that the call had none.
    pub media: Option<VconMedia>,
}

/// Whether an export carries the audio the run retained.
///
/// A typed enum rather than a free string, so the schema a client reads names
/// both words and a third is refused before the tool runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "lowercase")]
pub enum VconMedia {
    /// Retained audio travels inline as a `recording` Dialog Object, under the
    /// inline-media budget. The default.
    #[default]
    Inline,
    /// No audio is considered. The container is signaling-only and says so.
    Omit,
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
    /// Advertised as an object rather than as "anything at all". `schemars`
    /// renders `serde_json::Value` as a schema with no validation keyword,
    /// which the MCP Inspector's strict lint calls out as the object-literal
    /// spelling of a bare `true` -- a client is told nothing about the shape,
    /// including the one thing that is always true of it.
    #[schemars(with = "Option<std::collections::BTreeMap<String, serde_json::Value>>")]
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
/// per [draft-ietf-vcon-vcon-core-04 section 2.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3), and an agent that has to parse a document out of a document to
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
    /// Advertised as an object rather than as "anything at all". `schemars`
    /// renders `serde_json::Value` as a schema with no validation keyword,
    /// which the MCP Inspector's strict lint calls out as the object-literal
    /// spelling of a bare `true` -- a client is told nothing about the shape,
    /// including the one thing that is always true of it.
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
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
    /// The containers, ordered by the dialog's `created_at`, then Call-ID.
    pub containers: Vec<ExportedContainer>,
    /// How many are in this response.
    pub returned: usize,
    /// How many dialogs the request selected, across the whole store.
    pub total_matched: usize,
    /// Whether matches remain after this page. Pass `next_cursor` back to
    /// continue.
    pub truncated: bool,
    /// Opaque cursor (`<RFC 3339 created_at>|<Call-ID>` of the last container)
    /// to pass to the next call. Null on the final page.
    pub next_cursor: Option<String>,
    /// Which capture this answer came from, and which revision of its stores.
    ///
    /// A cursor is only meaningful within one capture. `open_capture` can
    /// replace the whole dialog set between two pages, and a page carrying a
    /// different `instance` than the page before it is from another capture.
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
}

/// The answer `validate_vcon` gives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ValidateVconResponse {
    /// Version of this envelope.
    pub schema_version: u32,
    /// `valid` or `invalid`.
    pub verdict: String,
    /// Where the schema this was checked against lives in the sipnab
    /// repository.
    pub schema_path: String,
    /// The `$id` that schema declares.
    pub schema_id: String,
    /// Every finding. Empty on a clean pass.
    pub errors: Vec<ValidationFinding>,
    /// The dialog whose freshly exported container was validated, when the
    /// caller named one rather than supplying a document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
}

/// Parameters for `vcon_spool_status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct VconSpoolStatusParams {
    /// Maximum failed records to return (default 50, ceiling `--mcp-max-rows`, itself 1000 unless the operator says otherwise).
    ///
    /// The three counts are never bounded; only the list of failed records is.
    pub limit: Option<u32>,
    /// Cursor: pass back the previous response's `next_cursor` verbatim.
    /// Omit on the first call.
    pub cursor: Option<String>,
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

/// One `export_vcon` request, after its arguments were read.
///
/// Grouped so the builder takes one value: which dialogs, how many per page,
/// where the previous page ended, and whether the audio travels.
struct ExportRequest {
    /// Which dialogs.
    selection: Selection,
    /// Most containers in this page.
    limit: usize,
    /// Where the previous page ended, when there was one.
    cursor: Option<crate::mcp::shape::Cursor>,
    /// Whether retained audio travels inline.
    media: VconMedia,
}

impl ExportRequest {
    /// The whole of one dialog, audio included: the request `validate_vcon`
    /// and the `sipnab://vcon/{call_id}` resource make.
    fn one(call_id: String) -> Self {
        Self {
            selection: Selection::One(call_id),
            limit: 1,
            cursor: None,
            media: VconMedia::Inline,
        }
    }
}

#[tool_router(router = vcon_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Count the vCon export spool, and read why each refused container was
    /// refused.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when this run was not given
    /// `--export-vcon-dir`; `internal_error` (-32603) when a directory exists
    /// and cannot be read.
    #[tool(
        name = "vcon_spool_status",
        description = "Counts the vCon export spool (--export-vcon-dir): \
                       containers pending, delivered and failed, and for each \
                       failed container the record the forwarder wrote beside \
                       it -- the store's status, the method and URL, and the \
                       start of the store's answer. A SNAPSHOT of files on \
                       disk at as_of: the forwarder (sipnab --vcon-forward) is \
                       a separate process, and this tool sends, fetches, moves \
                       and deletes nothing. Reads the forwarder's default \
                       delivered/ and failed/ directories beside the spool. \
                       The failed list is bounded by limit and paged with \
                       cursor. Returns an error when this run was started \
                       without --export-vcon-dir.",
        output_schema = schema_for_output::<crate::app::vcon_spool::SpoolStatus>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn vcon_spool_status(
        &self,
        Parameters(params): Parameters<VconSpoolStatusParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let spool = self.vcon_spool.as_deref().ok_or_else(|| {
            crate::mcp::errors::refuse(
                crate::mcp::errors::Reason::NotEnabled,
                "this run has no vCon export spool: start sipnab with \
                 --export-vcon-when <EXPR> --export-vcon-dir <DIR>, and this \
                 tool reads that directory",
            )
        })?;
        let page = crate::app::vcon_spool::SpoolPage {
            after: params.cursor.as_deref(),
            limit: resolve_limit_with_cap(params.limit, self.row_cap),
        };
        let mut response = crate::app::vcon_spool::snapshot(spool, page, chrono::Utc::now())
            .map_err(|e| rmcp::ErrorData::internal_error(e, None))?;
        // The MCP door's envelope, and its only difference from the other
        // doors: a store's answer is text another system wrote, so it is cut
        // to `--mcp-max-body-bytes` and fenced as every such text on this
        // surface is.
        for failure in &mut response.failures {
            if let Some(record) = failure.record.as_mut() {
                record.body = record.body.take().map(|b| {
                    crate::mcp::shape::fence(&crate::mcp::shape::truncate_string(&b, self.body_cap))
                });
            }
        }
        let value = serde_json::to_value(&response).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("spool status serialization failed: {e}"), None)
        })?;
        // The record bodies are text a vCon store wrote. They are fenced, and
        // the note says what the fence means.
        Ok(CallToolResult::success(vec![
            ContentBlock::json(value)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }

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
                       SET -- use the filter rather than looping call_id, \
                       bound it with limit, and page it by passing \
                       next_cursor back as cursor. media \"omit\" leaves the \
                       audio out and each container says so; the default, \
                       \"inline\", carries it. The same container is readable \
                       as the resource sipnab://vcon/{call_id}. These are \
                       OBSERVER vCons: sipnab \
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
        // Parsed the way every other paged tool parses it, and refused the
        // same way: restarting from the beginning on a malformed cursor would
        // loop a paging agent over the first page forever.
        let cursor = match params.cursor.as_deref() {
            Some(raw) => Some(crate::mcp::shape::parse_cursor(raw).map_err(|e| {
                crate::mcp::errors::refuse_param(
                    crate::mcp::errors::Reason::InvalidValue,
                    "cursor",
                    e,
                )
            })?),
            None => None,
        };
        let response = self.export_containers(&ExportRequest {
            selection,
            limit: resolve_limit_with_cap(params.limit, self.row_cap),
            cursor,
            media: params.media.unwrap_or_default(),
        })?;

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
                       draft-ietf-vcon-vcon-core-04 schema, vendored \
                       unmodified (tests/schemas/vcon.schema.json). Takes a \
                       call_id, whose container is exported and then checked, \
                       or a container supplied verbatim -- one sipnab wrote, \
                       or one another producer did. Answers valid or invalid, \
                       with every finding's JSON Pointer, the schema keyword \
                       that refused it and what was wrong. Use it before \
                       handing containers to a conserver: a store that \
                       refuses one tells whoever POSTed it, not whoever built \
                       it.",
        output_schema = schema_for_output::<ValidateVconResponse>(),
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn validate_vcon(
        &self,
        Parameters(params): Parameters<ValidateVconParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let response = match (params.call_id, params.container) {
            (Some(_), Some(_)) => {
                return Err(errors::refuse(
                    Reason::ConflictingParams,
                    "`call_id` and `container` are alternatives: the first \
                     exports a dialog and checks what it produced, the second \
                     checks a document you already hold. Give one",
                ));
            }
            (None, None) => {
                return Err(errors::refuse(
                    Reason::MissingParam,
                    "give `call_id` to export a dialog and validate it, or \
                     `container` to validate a document you already hold",
                ));
            }
            (Some(call_id), None) => {
                let exported = self.export_containers(&ExportRequest::one(call_id.clone()))?;
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
                    return Err(errors::refuse_param(
                        Reason::InvalidValue,
                        "container",
                        "a vCon container is a JSON object; this is not one, so \
                         there is nothing to validate. Pass the container \
                         itself, not a string holding it",
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
            (Some(_), Some(_)) => Err(errors::refuse(
                Reason::ConflictingParams,
                "`call_id` and `filter` are alternatives, not a pair: one names \
                 a dialog, the other names a rule for choosing them. Give one",
            )),
            (None, None) => Err(errors::refuse(
                Reason::MissingParam,
                "give `call_id` for one dialog, or `filter` for every dialog it \
                 selects -- for example \"response_code >= 400\"",
            )),
            (Some(id), None) => Ok(Selection::One(id)),
            (None, Some(expression)) => {
                let compiled = self.compile_filter(Some(&expression))?.ok_or_else(|| {
                    errors::refuse_param(
                        Reason::InvalidValue,
                        "filter",
                        "an empty filter selects nothing and names nothing; omit \
                         it, or give an expression",
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
    ///
    /// Paged the way `list_dialogs` pages: matches are ordered by
    /// `(created_at, Call-ID)` before the cursor and the limit apply, because
    /// store order is insertion order and cutting it would let `next_cursor`
    /// skip dialogs that were never returned. `created_at` never changes, so a
    /// page boundary stays where it was put while the capture grows.
    #[cfg(feature = "vcon")]
    fn export_containers(
        &self,
        request: &ExportRequest,
    ) -> Result<ExportVconResponse, rmcp::ErrorData> {
        let selection = &request.selection;
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

        // Every match, counted and ordered; only the page is BUILT.
        // `total_matched` is the number an agent pages against, and it cannot
        // be known from a scan that stopped at the limit.
        let mut matched: Vec<&crate::sip::dialog::SipDialog> = ds
            .iter()
            .filter(|dialog| match selection {
                Selection::One(id) => dialog.call_id == *id,
                Selection::Matching(expr) => {
                    let streams: Vec<&crate::rtp::stream::RtpStream> =
                        ss.streams_for(&dialog.call_id).collect();
                    expr.matches_dialog(dialog, &streams, capture, delay)
                }
            })
            .collect();
        let total_matched = matched.len();
        crate::sort::sort_by_dyn(&mut matched, &mut |a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.call_id.cmp(&b.call_id))
        });
        let remaining: Vec<&crate::sip::dialog::SipDialog> = match &request.cursor {
            None => matched,
            Some(c) => matched
                .into_iter()
                .filter(|d| c.precedes(d.created_at, &d.call_id))
                .collect(),
        };
        let truncated = remaining.len() > request.limit;
        let page = &remaining[..remaining.len().min(request.limit)];
        let next_cursor = truncated
            .then(|| page.last())
            .flatten()
            .map(|d| crate::mcp::shape::format_cursor(d.created_at, &d.call_id));

        let mut containers = Vec::new();
        for dialog in page {
            let streams: Vec<&crate::rtp::stream::RtpStream> =
                ss.streams_for(&dialog.call_id).collect();

            // With `media: inline`, media is attempted always. When the run
            // retained no payload the decode fails, and its message -- which
            // reports what was MEASURED and never claims the call was silent
            // -- travels in the container instead of an absence the agent
            // would have to interpret. With `media: omit` nothing is decoded,
            // and the container records `not-considered`: the outcome the
            // exporter already has for an export that did not look at media.
            let decoded = match request.media {
                VconMedia::Inline => Some(crate::rtp::audio_export::decode_dialog_audio(&streams)),
                VconMedia::Omit => None,
            };
            let reason = decoded
                .as_ref()
                .and_then(|d| d.as_ref().err())
                .map_or_else(String::new, ToString::to_string);
            let audio = match decoded.as_ref() {
                None => ObservedAudio::NotConsidered,
                Some(Ok(audio)) => ObservedAudio::Decoded(audio),
                Some(Err(_)) => ObservedAudio::NothingToDecode(&reason),
            };

            let media = crate::output::vcon::media_quality_for(&ss, &dialog.call_id);
            let context = ExportContext {
                capture_id: crate::output::vcon::dialog_capture_id(dialog),
                facts: &facts,
                analysis: Some(&analysis),
                max_inline_media_bytes: budget,
                media: &media,
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
            return Err(errors::refuse_param(
                Reason::NotFound,
                "call_id",
                format!("call_id '{id}' not found"),
            ));
        }

        Ok(ExportVconResponse {
            // Still 1: `next_cursor` is an added member, and every member a
            // version-1 reader knows keeps its meaning.
            schema_version: 1,
            returned: containers.len(),
            truncated,
            next_cursor,
            containers,
            total_matched,
            capture_identity,
        })
    }

    /// The text `sipnab://vcon/{call_id}` reads as: the container
    /// `export_vcon` builds for that dialog, audio inline.
    ///
    /// Built by [`Self::export_containers`], the function behind
    /// `export_vcon` and `validate_vcon`, so the resource door and the tool
    /// door cannot come to build different containers for one dialog.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for a Call-ID the store does not hold, and
    /// for a container longer than `max_bytes`, which the refusal states
    /// alongside the tool that carries it instead.
    #[cfg(feature = "vcon")]
    pub(crate) fn vcon_resource(
        &self,
        call_id: &str,
        max_bytes: u64,
    ) -> Result<String, rmcp::ErrorData> {
        let exported = self.export_containers(&ExportRequest::one(call_id.to_owned()))?;
        let container = exported
            .containers
            .into_iter()
            .next()
            .map(|c| c.container)
            .ok_or_else(|| {
                rmcp::ErrorData::internal_error(
                    format!("call_id '{call_id}' exported no container"),
                    None,
                )
            })?;
        let text = serde_json::to_string(&container).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("vCon serialization failed: {e}"), None)
        })?;
        crate::mcp::server::refuse_past_resource_limit(
            &format!("the vCon for '{call_id}'"),
            u64::try_from(text.len()).unwrap_or(u64::MAX),
            max_bytes,
            "call export_vcon with this call_id, which is bounded by \
             --mcp-max-rows rather than by the resource limit, or with \
             media \"omit\" to leave the audio out",
        )?;
        Ok(text)
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
            // 2: the core-04 schema left nothing to excuse, so `deviations`,
            // `explanations` and the `valid-except-documented-deviation`
            // verdict are gone.
            schema_version: 2,
            verdict: report.verdict.as_str().to_owned(),
            schema_path: report.schema_path.to_owned(),
            schema_id: report.schema_id,
            errors: report.errors.iter().map(finding_row).collect(),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    use parking_lot::RwLock;
    use std::sync::Arc;

    type TestError = Box<dyn std::error::Error>;

    /// One instant every fixture shares, so a uuid's timestamp half can never
    /// be what tells two dialogs apart.
    fn ts() -> Result<chrono::DateTime<chrono::Utc>, TestError> {
        Ok(
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0)
                .single()
                .ok_or("a real instant")?,
        )
    }

    /// Parse `raw` as SIP between localhost endpoints.
    fn parse_at(raw: &[u8]) -> Result<crate::sip::SipMessage, TestError> {
        let local = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        Ok(crate::sip::parser::parse_sip(
            raw,
            ts()?,
            local,
            local,
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .map_err(|e| format!("fixture parses as SIP: {e:?}"))?)
    }

    /// A minimal well-formed INVITE for `call_id`.
    fn invite(call_id: &str) -> Result<crate::sip::SipMessage, TestError> {
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
    fn final_response(
        call_id: &str,
        code: u16,
        reason: &str,
    ) -> Result<crate::sip::SipMessage, TestError> {
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
    fn server_with(calls: &[(&str, u16)]) -> Result<SipnabMcp, TestError> {
        let mut ds = DialogStore::new(100, false);
        Ok({
            for (call_id, code) in calls {
                ds.process_message(invite(call_id)?);
                ds.process_message(final_response(call_id, *code, "Fixture")?);
            }
            SipnabMcp::new(
                Arc::new(RwLock::new(ds)),
                Arc::new(RwLock::new(StreamStore::new(100))),
            )
        })
    }

    /// The payload block of a result, skipping the untrusted-content note.
    ///
    /// Only a build carrying the exporter ever gets a payload; the other one
    /// gets a refusal, which is a message rather than a document.
    #[cfg(feature = "vcon")]
    fn payload(result: &CallToolResult) -> Result<serde_json::Value, TestError> {
        let note = crate::mcp::shape::untrusted_note();
        let text = result
            .content
            .iter()
            .filter_map(rmcp::model::ContentBlock::as_text)
            .map(|t| t.text.clone())
            .find(|t| *t != note)
            .ok_or("a payload block that is not the note")?;
        Ok(serde_json::from_str(&text).map_err(|e| format!("the payload is JSON: {e:?}"))?)
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
    async fn exported(
        server: &SipnabMcp,
        params: ExportVconParams,
    ) -> Result<serde_json::Value, TestError> {
        let result = server
            .export_vcon(Parameters(params))
            .await
            .map_err(|e| format!("the export should succeed: {e:?}"))?;
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
    async fn export_vcon_returns_a_structured_container_for_a_known_call() -> Result<(), TestError>
    {
        let server = server_with(&[("vcon-ok@x", 200)])?;
        let v = exported(
            &server,
            ExportVconParams {
                call_id: Some("vcon-ok@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await?;

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
            .ok_or("parties is an array")?;
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
        Ok(())
    }

    /// Two different dialogs answer with two different containers.
    ///
    /// Without this a handler returning one constant satisfies every other
    /// assertion here.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn export_vcon_discriminates_between_two_dialogs() -> Result<(), TestError> {
        let server = server_with(&[("vcon-a@x", 200), ("vcon-b@x", 200)])?;
        let a = exported(
            &server,
            ExportVconParams {
                call_id: Some("vcon-a@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await?;
        let b = exported(
            &server,
            ExportVconParams {
                call_id: Some("vcon-b@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await?;

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
        Ok(())
    }

    /// Re-exporting one dialog keeps its identifier AND its digest.
    ///
    /// The assertion that discriminates, and the opposite of the one above: an
    /// exporter minting a fresh uuid per call passes
    /// `export_vcon_discriminates_between_two_dialogs` and breaks every
    /// consumer that deduplicates on the identifier.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn export_vcon_is_stable_across_calls_for_one_dialog() -> Result<(), TestError> {
        let server = server_with(&[("vcon-stable@x", 200)])?;
        let params = || ExportVconParams {
            call_id: Some("vcon-stable@x".to_string()),
            ..ExportVconParams::default()
        };
        let first = exported(&server, params()).await?;
        let second = exported(&server, params()).await?;
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
        Ok(())
    }

    /// A digest is a SHA-256, spelled the way `sha256sum` spells one.
    ///
    /// The format is the interoperation. A digest an operator cannot paste
    /// beside a `--vcon-digest` line joins to nothing.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_digest_is_lowercase_hex_sha256() -> Result<(), TestError> {
        let v = exported(
            &server_with(&[("vcon-hex@x", 200)])?,
            ExportVconParams {
                call_id: Some("vcon-hex@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await?;
        let digest = v["containers"][0]["digest"]
            .as_str()
            .ok_or("a digest string")?;
        assert_eq!(digest.len(), 64, "SHA-256 is 32 bytes of hex: {digest}");
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "lowercase hex, the spelling `sha256sum` writes: {digest}"
        );
        Ok(())
    }

    /// An unknown Call-ID errors with invalid_params (-32602).
    ///
    /// Not `internal_error`, and emphatically not an empty success: an agent
    /// handed an empty list reads it as a capture that held no such call and
    /// moves on.
    #[tokio::test]
    async fn export_vcon_unknown_call_id_errors() -> Result<(), TestError> {
        let err = empty_server()
            .export_vcon(Parameters(ExportVconParams {
                call_id: Some("nonexistent@nowhere".to_string()),
                ..ExportVconParams::default()
            }))
            .await
            .err()
            .ok_or("unknown call_id must error")?;
        assert_eq!(code_of(err), -32602);
        Ok(())
    }

    /// A request naming neither a dialog nor a rule is refused.
    #[tokio::test]
    async fn export_vcon_refuses_a_request_that_selects_nothing() -> Result<(), TestError> {
        let err = empty_server()
            .export_vcon(Parameters(ExportVconParams::default()))
            .await
            .err()
            .ok_or("a request selecting nothing must be refused")?;
        let message = message_of(err);
        assert!(
            message.contains("call_id") && message.contains("filter"),
            "the refusal must name both ways to select: {message}"
        );
        Ok(())
    }

    /// A request naming both is refused, as the CLI refuses the same pair.
    #[tokio::test]
    async fn export_vcon_refuses_a_call_id_and_a_filter_together() -> Result<(), TestError> {
        let err = empty_server()
            .export_vcon(Parameters(ExportVconParams {
                call_id: Some("a@x".to_string()),
                filter: Some("response_code >= 400".to_string()),
                ..ExportVconParams::default()
            }))
            .await
            .err()
            .ok_or("two selections must be refused")?;
        let json = serde_json::to_value(err).map_err(|e| format!("the error serializes: {e:?}"))?;
        assert_eq!(json["code"], -32602);
        assert!(
            json["message"]
                .as_str()
                .unwrap_or_default()
                .contains("alternatives"),
            "the refusal must say the two are alternatives rather than \
             silently preferring one: {json}"
        );
        Ok(())
    }

    /// An unparseable filter is refused by name.
    #[tokio::test]
    async fn export_vcon_refuses_an_unparseable_filter() -> Result<(), TestError> {
        let err = empty_server()
            .export_vcon(Parameters(ExportVconParams {
                filter: Some("response_code >>> 400".to_string()),
                ..ExportVconParams::default()
            }))
            .await
            .err()
            .ok_or("a broken filter must be refused")?;
        assert_eq!(code_of(err), -32602);
        Ok(())
    }

    // ── export_vcon: the filter form (RV5) ───────────────────────────

    /// RV5: one call exports every dialog a filter selects.
    ///
    /// The whole point. An agent asked to export every failed call used to
    /// list dialogs and then issue one `export_vcon` per row -- hundreds of
    /// round trips on a real capture to do what one CLI invocation does.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_filter_exports_every_matching_dialog_in_one_call() -> Result<(), TestError> {
        let server = server_with(&[
            ("ok@x", 200),
            ("busy@x", 486),
            ("gone@x", 404),
            ("fine@x", 200),
        ])?;
        let v = exported(
            &server,
            ExportVconParams {
                filter: Some("response_code >= 400".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await?;

        assert_eq!(v["total_matched"], 2, "two calls failed: {v}");
        assert_eq!(v["returned"], 2, "and both containers came back: {v}");
        assert_eq!(v["truncated"], false, "nothing was cut: {v}");

        let mut ids: Vec<&str> = v["containers"]
            .as_array()
            .ok_or("containers is an array")?
            .iter()
            .map(|c| c["call_id"].as_str().unwrap_or_default())
            .collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            vec!["busy@x", "gone@x"],
            "the filter must select the failures and only the failures: {v}"
        );
        Ok(())
    }

    /// RV5: the answer is bounded, and says it was.
    ///
    /// A container is a large answer and a filter can select a whole capture.
    /// `total_matched` is what an agent pages against, so it has to be the
    /// count across the STORE rather than the length of the list it got.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_filter_is_bounded_and_reports_what_it_left_behind() -> Result<(), TestError> {
        let server = server_with(&[("a@x", 486), ("b@x", 486), ("c@x", 486)])?;
        let v = exported(
            &server,
            ExportVconParams {
                filter: Some("response_code >= 400".to_string()),
                limit: Some(1),
                ..ExportVconParams::default()
            },
        )
        .await?;

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
        Ok(())
    }

    /// A filter matching nothing is an empty answer, not an error.
    ///
    /// "No call failed" is a FINDING. Refusing it the way an unknown Call-ID
    /// is refused would make a clean capture look like a broken request.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_filter_that_matches_nothing_answers_with_an_empty_set() -> Result<(), TestError> {
        let v = exported(
            &server_with(&[("ok@x", 200)])?,
            ExportVconParams {
                filter: Some("response_code >= 400".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await?;
        assert_eq!(v["total_matched"], 0, "{v}");
        assert_eq!(v["returned"], 0, "{v}");
        assert_eq!(v["truncated"], false, "nothing was withheld: {v}");
        assert!(
            v["containers"].as_array().is_some_and(Vec::is_empty),
            "an empty set is an empty array, not a missing key: {v}"
        );
        Ok(())
    }

    // ── the omissions reach the caller (RV7) ─────────────────────────

    /// RV7: the caveat in the response is the caveat in the container.
    ///
    /// Not a second sentence written beside it. The container already carries
    /// the completeness note, inside an attachment whose body is JSON TEXT per
    /// [draft-ietf-vcon-vcon-core-04 section 2.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3) -- so an agent would have to parse a document out of a document to
    /// read it. This is the SAME string, lifted, and the assertion is that it
    /// is the same one rather than a paraphrase that can drift.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn the_response_carries_the_containers_own_caveat() -> Result<(), TestError> {
        let v = exported(
            &server_with(&[("caveat@x", 200)])?,
            ExportVconParams {
                call_id: Some("caveat@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await?;
        let entry = &v["containers"][0];

        let inside: serde_json::Value = serde_json::from_str(
            entry["container"]["analysis"][0]["body"]
                .as_str()
                .ok_or("the analysis body is JSON text")?,
        )
        .map_err(|e| format!("the analysis body parses: {e:?}"))?;
        let in_container = inside["capture_completeness"]["note"]
            .as_str()
            .ok_or("the container carries a note")?;

        assert_eq!(
            entry["completeness"]["note"].as_str(),
            Some(in_container),
            "the response's caveat and the container's must be one string: {entry}"
        );
        assert!(
            !in_container.is_empty(),
            "premise: there must be a caveat to carry"
        );
        Ok(())
    }

    /// RV7: the applied inline-media bound is stated, not the compiled default.
    ///
    /// An operator who set `--vcon-max-inline-media` and reads the default
    /// here goes looking for a limit nothing enforced. The pair of assertions
    /// is what makes it a measurement: the default appears when nothing was
    /// set, and the setting appears when something was.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn the_response_states_the_inline_media_bound_it_enforced() -> Result<(), TestError> {
        let params = || ExportVconParams {
            call_id: Some("bound@x".to_string()),
            ..ExportVconParams::default()
        };

        let unset = exported(&server_with(&[("bound@x", 200)])?, params()).await?;
        assert_eq!(
            unset["containers"][0]["completeness"]["max_inline_media_bytes"]
                .as_u64()
                .map(usize::try_from),
            Some(Ok(crate::output::vcon::MAX_INLINE_MEDIA_BYTES)),
            "with nothing set, the measured default is what was enforced: {unset}"
        );

        let tightened = server_with(&[("bound@x", 200)])?.with_max_inline_media_bytes(Some(4096));
        let set = exported(&tightened, params()).await?;
        assert_eq!(
            set["containers"][0]["completeness"]["max_inline_media_bytes"], 4096,
            "the number that was APPLIED, never the compiled-in one: {set}"
        );
        Ok(())
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
    async fn the_response_states_the_media_case_and_keeps_complete_honest() -> Result<(), TestError>
    {
        let v = exported(
            &server_with(&[("clean@x", 200)])?,
            ExportVconParams {
                call_id: Some("clean@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await?;
        let completeness = &v["containers"][0]["completeness"];
        let rows = completeness["omissions"]
            .as_array()
            .ok_or("an omissions array, present even when it is empty")?;

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
        Ok(())
    }

    /// RV7: a retention loss becomes a row, and the row and the prose agree.
    ///
    /// The store is sized so it cannot hold what it is given, which is the one
    /// omission a unit test can produce without a capture: every other counter
    /// is a process-global the pipeline sets.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_retention_loss_reaches_the_response_as_a_row() -> Result<(), TestError> {
        let mut ds = DialogStore::new(1, false);
        for id in ["first@x", "second@x"] {
            ds.process_message(invite(id)?);
            ds.process_message(final_response(id, 200, "Fixture")?);
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
        .await?;
        let completeness = &v["containers"][0]["completeness"];
        let rows = completeness["omissions"]
            .as_array()
            .ok_or("an omissions array")?;

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
        Ok(())
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
    fn an_omission_row_is_the_wire_shape_of_the_carriers_row() -> Result<(), TestError> {
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
            serde_json::to_value(&row).map_err(|e| format!("serializes: {e:?}"))?,
            serde_json::to_value(&carrier).map_err(|e| format!("serializes: {e:?}"))?,
            "the tool's row and the carrier's row must be one wire shape"
        );
        Ok(())
    }

    // ── export_vcon: paging and media selection ──────────────────────

    /// The `call_id`s of one parsed `export_vcon` page, in response order.
    #[cfg(feature = "vcon")]
    fn page_ids(v: &serde_json::Value) -> Vec<String> {
        v["containers"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| c["call_id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A filter selecting more dialogs than one page is walked to the end by
    /// following `next_cursor`, and every dialog arrives exactly once.
    ///
    /// The five dialogs share one `created_at` (every fixture message is
    /// stamped with `ts()`), so the walk crosses page boundaries INSIDE a tie
    /// group. That is the case the compound cursor's Call-ID half exists for:
    /// a bare-timestamp cursor drops the rest of the group or repeats it.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_cursor_pages_through_every_matching_dialog_exactly_once() -> Result<(), TestError> {
        let ids = ["p1@x", "p2@x", "p3@x", "p4@x", "p5@x"];
        // Inserted out of order, so the page order has to come from the sort
        // and not from the store's insertion order.
        let server = server_with(&[
            ("p3@x", 486),
            ("p1@x", 486),
            ("p5@x", 486),
            ("p2@x", 486),
            ("p4@x", 486),
        ])?;

        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            pages += 1;
            assert!(pages <= 5, "the walk did not terminate: {seen:?}");
            let v = exported(
                &server,
                ExportVconParams {
                    filter: Some("response_code >= 400".to_string()),
                    limit: Some(2),
                    cursor: cursor.clone(),
                    ..ExportVconParams::default()
                },
            )
            .await?;
            assert_eq!(
                v["total_matched"], 5,
                "the count is across the store on every page: {v}"
            );
            seen.extend(page_ids(&v));
            match v["next_cursor"].as_str() {
                Some(next) => {
                    assert_eq!(v["truncated"], true, "a cursor means more remain: {v}");
                    cursor = Some(next.to_owned());
                }
                None => {
                    assert_eq!(v["truncated"], false, "the last page says so: {v}");
                    break;
                }
            }
        }
        assert_eq!(pages, 3, "five dialogs at two per page is three pages");
        assert_eq!(
            seen,
            ids.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            "every dialog once, in (created_at, Call-ID) order"
        );
        Ok(())
    }

    /// `next_cursor` is the cursor `list_dialogs` mints for the same set.
    ///
    /// One cursor rule across the paged tools, so a cursor from either one
    /// means the same position. A second encoding would have to be learned,
    /// and would drift.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn the_cursor_is_the_one_list_dialogs_mints() -> Result<(), TestError> {
        let server = server_with(&[("c1@x", 486), ("c2@x", 486), ("c3@x", 486)])?;
        let filter = Some("response_code >= 400".to_string());
        let v = exported(
            &server,
            ExportVconParams {
                filter: filter.clone(),
                limit: Some(2),
                ..ExportVconParams::default()
            },
        )
        .await?;
        let listed = server
            .list_dialogs(Parameters(crate::mcp::server::ListDialogsParams {
                filter,
                limit: Some(2),
                ..Default::default()
            }))
            .await
            .map_err(|e| format!("list_dialogs answers: {e:?}"))?;
        let listed = payload(&listed)?;
        assert!(v["next_cursor"].is_string(), "premise: a second page: {v}");
        assert_eq!(
            v["next_cursor"], listed["next_cursor"],
            "export_vcon and list_dialogs must mint one cursor for one position"
        );
        Ok(())
    }

    /// A cursor that is not one is refused the way `list_dialogs` refuses it,
    /// rather than restarting from the beginning. A restart would loop a
    /// paging agent over the first page forever.
    #[tokio::test]
    async fn export_vcon_refuses_a_malformed_cursor() -> Result<(), TestError> {
        let err = server_with(&[("m@x", 486)])?
            .export_vcon(Parameters(ExportVconParams {
                filter: Some("response_code >= 400".to_string()),
                cursor: Some("not-a-time|m@x".to_string()),
                ..ExportVconParams::default()
            }))
            .await
            .err()
            .ok_or("a malformed cursor must be refused")?;
        let json = serde_json::to_value(err).map_err(|e| format!("serializes: {e:?}"))?;
        assert_eq!(json["code"], -32602, "{json}");
        assert!(
            json["message"]
                .as_str()
                .is_some_and(|m| m.contains("RFC 3339")),
            "the refusal names the format the cursor must have: {json}"
        );
        Ok(())
    }

    /// A cursor past every match answers with an empty final page, and the
    /// envelope still says how many matched.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_cursor_past_the_end_answers_an_empty_final_page() -> Result<(), TestError> {
        let server = server_with(&[("e1@x", 486)])?;
        let v = exported(
            &server,
            ExportVconParams {
                filter: Some("response_code >= 400".to_string()),
                cursor: Some(crate::mcp::shape::format_cursor(ts()?, "zzzz")),
                ..ExportVconParams::default()
            },
        )
        .await?;
        assert_eq!(v["returned"], 0, "{v}");
        assert_eq!(v["total_matched"], 1, "{v}");
        assert!(v["next_cursor"].is_null(), "{v}");
        assert_eq!(v["truncated"], false, "{v}");
        Ok(())
    }

    /// A server holding one dialog with a decodable PCMU stream retained, so
    /// the export has audio to carry or to leave out.
    #[cfg(feature = "vcon")]
    fn server_with_audio(call_id: &str) -> Result<SipnabMcp, TestError> {
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream::{RtpStream, StreamKey};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut ds = DialogStore::new(100, false);
        ds.process_message(invite(call_id)?);
        ds.process_message(final_response(call_id, 200, "Fixture")?);

        let mut ss = StreamStore::new(100);
        for (ssrc, port) in [(0x1111_1111_u32, 20000_u16), (0x2222_2222, 30000)] {
            let key = StreamKey::new(
                ssrc,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), port + 1),
            );
            let hdr = RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 0,
                sequence: 1,
                timestamp: 0,
                ssrc,
                payload_offset: 12,
            };
            let mut stream = RtpStream::new(key, &hdr, ts()?);
            stream.codec = Some("PCMU".to_string());
            stream.associated_dialog = Some(call_id.to_string());
            stream.payload_buffer = (0..10_u32).map(|i| (i * 160, vec![0xFF; 160])).collect();
            ss.insert_for_test(stream);
        }
        Ok(SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(ss)),
        ))
    }

    /// Whether a container carries audio: a `recording` Dialog Object with an
    /// inline `body`.
    ///
    /// The `body` is the test, not the type. core-04 types the signaling
    /// Dialog Object of a call that was set up as `recording` too, so a type
    /// check alone finds one in every signaling-only container.
    #[cfg(feature = "vcon")]
    fn has_recording(container: &serde_json::Value) -> bool {
        container["dialog"].as_array().is_some_and(|d| {
            d.iter()
                .any(|o| o["type"] == "recording" && o["body"].is_string())
        })
    }

    /// The `capture_completeness` object the container itself carries.
    #[cfg(feature = "vcon")]
    fn carried_completeness(container: &serde_json::Value) -> Result<serde_json::Value, TestError> {
        let body: serde_json::Value = serde_json::from_str(
            container["analysis"][0]["body"]
                .as_str()
                .ok_or("the analysis body is JSON text")?,
        )
        .map_err(|e| format!("the analysis body parses: {e:?}"))?;
        Ok(body["capture_completeness"].clone())
    }

    /// `media: "inline"` (the default) carries the retained audio, and
    /// `media: "omit"` leaves it out and says so INSIDE the container.
    ///
    /// The omission is recorded with the outcome sipnab already uses for an
    /// export that did not consider media, `not-considered`, so a reader of
    /// the container alone learns that the export left the audio out rather
    /// than concluding the call had none. Both containers must stay valid
    /// against the vendored core-04 schema.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn media_omit_leaves_the_audio_out_and_the_container_says_so() -> Result<(), TestError> {
        let server = server_with_audio("audio@x")?;
        let ask = |media: Option<VconMedia>| ExportVconParams {
            call_id: Some("audio@x".to_string()),
            media,
            ..ExportVconParams::default()
        };

        for (label, v) in [
            ("default", exported(&server, ask(None)).await?),
            (
                "inline",
                exported(&server, ask(Some(VconMedia::Inline))).await?,
            ),
        ] {
            let entry = &v["containers"][0];
            assert!(
                has_recording(&entry["container"]),
                "{label}: the retained audio travels inline: {entry}"
            );
            assert_eq!(
                entry["completeness"]["media"], "carried",
                "{label}: {entry}"
            );
            let report = crate::output::vcon_schema::validate(&entry["container"]);
            assert_eq!(
                report.verdict.as_str(),
                "valid",
                "{label}: {:?}",
                report.errors
            );
        }

        let omitted = exported(&server, ask(Some(VconMedia::Omit))).await?;
        let entry = &omitted["containers"][0];
        assert!(
            !has_recording(&entry["container"]),
            "media omit must leave the audio out: {entry}"
        );
        assert_eq!(entry["completeness"]["media"], "not-considered", "{entry}");
        let carried = carried_completeness(&entry["container"])?;
        assert_eq!(
            carried["media"], "not-considered",
            "the container itself must state the omission: {carried}"
        );
        assert!(
            carried["note"]
                .as_str()
                .is_some_and(|n| n.contains("SIGNALING ONLY")),
            "the caveat says this export carries no media: {carried}"
        );
        let report = crate::output::vcon_schema::validate(&entry["container"]);
        assert_eq!(report.verdict.as_str(), "valid", "{:?}", report.errors);
        Ok(())
    }

    /// `media` takes two words and refuses a third, naming the two.
    #[test]
    fn media_takes_inline_or_omit_and_nothing_else() -> Result<(), TestError> {
        let parse =
            |m: &str| serde_json::from_value::<ExportVconParams>(serde_json::json!({"media": m}));
        assert_eq!(
            parse("inline").map_err(|e| e.to_string())?.media,
            Some(VconMedia::Inline)
        );
        assert_eq!(
            parse("omit").map_err(|e| e.to_string())?.media,
            Some(VconMedia::Omit)
        );
        let refused = parse("url")
            .err()
            .ok_or("an unknown word must be refused")?;
        let message = refused.to_string();
        assert!(
            message.contains("inline") && message.contains("omit"),
            "the refusal names the vocabulary: {message}"
        );
        Ok(())
    }

    // ── the sipnab://vcon/{call_id} resource ─────────────────────────

    /// The container with its write time removed.
    ///
    /// `created_at` is the moment sipnab wrote the container, so two builds of
    /// one dialog differ there and nowhere else.
    #[cfg(feature = "vcon")]
    fn without_write_time(mut container: serde_json::Value) -> serde_json::Value {
        if let Some(obj) = container.as_object_mut() {
            obj.remove("created_at");
        }
        container
    }

    /// Reading `sipnab://vcon/{call_id}` returns the container `export_vcon`
    /// builds for the same dialog, and it is valid against core-04.
    ///
    /// Equal apart from `created_at`, which is the write time. Same `uuid`,
    /// same parties, same Dialog Objects, same completeness carrier: one
    /// builder behind both doors.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn the_vcon_resource_is_the_container_export_vcon_builds() -> Result<(), TestError> {
        let server = server_with(&[("res@x", 200), ("other@x", 486)])?;
        let text = server
            .vcon_resource("res@x", u64::MAX)
            .map_err(|e| format!("the resource reads: {e:?}"))?;
        let from_resource: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("the resource is JSON: {e:?}"))?;
        let from_tool = exported(
            &server,
            ExportVconParams {
                call_id: Some("res@x".to_string()),
                ..ExportVconParams::default()
            },
        )
        .await?["containers"][0]["container"]
            .clone();

        assert_eq!(
            from_resource["dialog"][0]["sip_call_id"], "res@x",
            "the resource names the dialog asked for: {from_resource}"
        );
        assert_eq!(
            without_write_time(from_resource.clone()),
            without_write_time(from_tool),
            "the resource and the tool must build one container"
        );
        let report = crate::output::vcon_schema::validate(&from_resource);
        assert_eq!(report.verdict.as_str(), "valid", "{:?}", report.errors);
        Ok(())
    }

    /// A Call-ID the store does not hold is refused with -32602, naming it.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_vcon_resource_refuses_an_unknown_call_id() -> Result<(), TestError> {
        let err = server_with(&[("known@x", 200)])?
            .vcon_resource("unknown@x", u64::MAX)
            .err()
            .ok_or("an unknown Call-ID must be refused")?;
        let json = serde_json::to_value(err).map_err(|e| format!("serializes: {e:?}"))?;
        assert_eq!(json["code"], -32602, "{json}");
        assert!(
            json["message"]
                .as_str()
                .is_some_and(|m| m.contains("unknown@x")),
            "{json}"
        );
        Ok(())
    }

    /// A container past the resource bound is refused, and the refusal states
    /// its size, the bound, and the tool that carries it instead.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_vcon_resource_is_refused_past_the_size_bound() -> Result<(), TestError> {
        let server = server_with(&[("big@x", 200)])?;
        let fits = server
            .vcon_resource("big@x", u64::MAX)
            .map_err(|e| format!("unbounded, it reads: {e:?}"))?;
        let size = u64::try_from(fits.len()).map_err(|e| format!("{e:?}"))?;

        let at_bound = server.vcon_resource("big@x", size + 64);
        assert!(at_bound.is_ok(), "a container under the bound is served");

        let err = server
            .vcon_resource("big@x", 16)
            .err()
            .ok_or("a container past the bound must be refused")?;
        let json = serde_json::to_value(err).map_err(|e| format!("serializes: {e:?}"))?;
        assert_eq!(json["code"], -32602, "{json}");
        let message = json["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("16-byte resource limit") && message.contains("export_vcon"),
            "the refusal states the bound and the way around it: {message}"
        );
        Ok(())
    }

    // ── vcon_spool_status ────────────────────────────────────────────

    /// A `vcon_spool_status` answer, parsed.
    #[cfg(feature = "vcon")]
    async fn spool_status(
        server: &SipnabMcp,
        params: VconSpoolStatusParams,
    ) -> Result<serde_json::Value, TestError> {
        let result = server
            .vcon_spool_status(Parameters(params))
            .await
            .map_err(|e| format!("the status should answer: {e:?}"))?;
        payload(&result)
    }

    /// Write `bytes` to `dir/name`, creating `dir`.
    fn put(dir: &std::path::Path, name: &str, bytes: &[u8]) -> Result<(), TestError> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join(name), bytes)?;
        Ok(())
    }

    /// Every file under `dir`, relative, sorted, with its bytes: what the tool
    /// must leave exactly as it found it.
    fn tree(dir: &std::path::Path) -> Result<Vec<(String, Vec<u8>)>, TestError> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d)? {
                let path = entry?.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let rel = path.strip_prefix(dir)?.display().to_string();
                    out.push((rel, std::fs::read(&path)?));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// One failure record, in the shape the forwarder writes.
    fn record(file: &str, status: u16, body: &str) -> String {
        serde_json::json!({
            "at": "2026-10-07T12:00:00Z",
            "body": body,
            "body_truncated": false,
            "file": file,
            "method": "POST",
            "reason": null,
            "status": status,
            "url": "https://vcon.example.com/v1/vcons",
        })
        .to_string()
    }

    /// An empty spool answers zeros, says when it looked, and says it is a
    /// snapshot of files rather than the forwarder's own account.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn an_empty_spool_answers_zeros_as_a_dated_snapshot() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let server = empty_server().with_vcon_spool(dir.path());
        let v = spool_status(&server, VconSpoolStatusParams::default()).await?;

        assert_eq!(v["pending"], 0, "{v}");
        assert_eq!(v["delivered"], 0, "{v}");
        assert_eq!(v["failed"], 0, "{v}");
        assert_eq!(v["spool"]["exists"], true, "{v}");
        assert!(v["failures"].as_array().is_some_and(Vec::is_empty), "{v}");
        let as_of = v["as_of"].as_str().ok_or("an as_of instant")?;
        chrono::DateTime::parse_from_rfc3339(as_of)
            .map_err(|e| format!("as_of is RFC 3339: {as_of}: {e:?}"))?;
        assert!(
            v["note"].as_str().is_some_and(|n| n.contains("snapshot")),
            "the answer must say it is a snapshot of files: {v}"
        );
        Ok(())
    }

    /// A spool holding every kind of file is counted by the forwarder's own
    /// rules, and nothing in it is moved, removed or rewritten.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_mixed_spool_is_counted_and_left_untouched() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let spool = dir.path();
        put(spool, "a.vcon.json", b"{}")?;
        put(spool, "b.vcon.json", b"{}")?;
        // Staging files and other names are not containers.
        put(spool, ".c.vcon.json.partial", b"{")?;
        put(spool, "notes.txt", b"x")?;
        put(&spool.join("delivered"), "d1.vcon.json", b"{}")?;
        put(&spool.join("failed"), "f1.vcon.json", b"{}")?;
        put(
            &spool.join("failed"),
            "f1.vcon.json.error.json",
            record("f1.vcon.json", 422, "bad").as_bytes(),
        )?;
        put(&spool.join("failed"), "f2.vcon.json", b"{}")?;
        let before = tree(spool)?;

        let v = spool_status(
            &empty_server().with_vcon_spool(spool),
            VconSpoolStatusParams::default(),
        )
        .await?;
        assert_eq!(v["pending"], 2, "{v}");
        assert_eq!(v["delivered"], 1, "{v}");
        assert_eq!(v["failed"], 2, "a record is not a container: {v}");
        assert_eq!(v["returned"], 2, "{v}");
        assert_eq!(v["failures"][0]["file"], "f1.vcon.json", "{v}");
        assert_eq!(v["failures"][0]["record"]["status"], 422, "{v}");
        assert_eq!(v["failures"][1]["file"], "f2.vcon.json", "{v}");
        assert!(
            v["failures"][1]["record"].is_null()
                && v["failures"][1]["record_problem"]
                    .as_str()
                    .is_some_and(|p| p.contains("f2.vcon.json.error.json")),
            "a failed container without its record says so: {v}"
        );

        assert_eq!(
            tree(spool)?,
            before,
            "the status tool must not move, delete or write anything"
        );
        Ok(())
    }

    /// Each failed record carries the store's answer as the forwarder kept
    /// it, and the list pages under `limit` with a cursor.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn failed_records_carry_the_stores_answer_and_page() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let failed = dir.path().join("failed");
        for (name, status, body) in [
            ("r1.vcon.json", 400, r#"{"detail":"vcon must have a uuid"}"#),
            ("r2.vcon.json", 409, "uuid already exists"),
            ("r3.vcon.json", 422, "unprocessable"),
        ] {
            put(&failed, name, b"{}")?;
            put(
                &failed,
                &format!("{name}.error.json"),
                record(name, status, body).as_bytes(),
            )?;
        }
        let server = empty_server().with_vcon_spool(dir.path());

        let first = spool_status(
            &server,
            VconSpoolStatusParams {
                limit: Some(2),
                ..VconSpoolStatusParams::default()
            },
        )
        .await?;
        assert_eq!(first["failed"], 3, "{first}");
        assert_eq!(first["returned"], 2, "{first}");
        assert_eq!(first["truncated"], true, "{first}");
        let r1 = &first["failures"][0]["record"];
        assert_eq!(r1["status"], 400, "{first}");
        // The store's answer is text another server wrote, so it arrives
        // fenced the way capture-derived text does.
        assert_eq!(
            r1["body"],
            crate::mcp::shape::fence(r#"{"detail":"vcon must have a uuid"}"#),
            "{first}"
        );
        assert_eq!(r1["method"], "POST", "{first}");
        assert_eq!(r1["url"], "https://vcon.example.com/v1/vcons", "{first}");
        assert_eq!(r1["at"], "2026-10-07T12:00:00Z", "{first}");
        assert_eq!(
            first["failures"][1]["record"]["body"],
            crate::mcp::shape::fence("uuid already exists")
        );

        let next = first["next_cursor"]
            .as_str()
            .ok_or("a cursor to the rest")?;
        let second = spool_status(
            &server,
            VconSpoolStatusParams {
                limit: Some(2),
                cursor: Some(next.to_owned()),
            },
        )
        .await?;
        assert_eq!(second["returned"], 1, "{second}");
        assert_eq!(second["failures"][0]["file"], "r3.vcon.json", "{second}");
        assert_eq!(second["failures"][0]["record"]["status"], 422, "{second}");
        assert_eq!(second["truncated"], false, "{second}");
        assert!(second["next_cursor"].is_null(), "{second}");
        Ok(())
    }

    /// A store answer longer than `--mcp-max-body-bytes` is cut to it, and the
    /// cut is marked.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_long_store_answer_is_cut_to_the_body_cap() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let failed = dir.path().join("failed");
        let long = "x".repeat(300);
        put(&failed, "long.vcon.json", b"{}")?;
        put(
            &failed,
            "long.vcon.json.error.json",
            record("long.vcon.json", 400, &long).as_bytes(),
        )?;
        let v = spool_status(
            &empty_server()
                .with_vcon_spool(dir.path())
                .with_body_cap(100),
            VconSpoolStatusParams::default(),
        )
        .await?;
        assert_eq!(
            v["failures"][0]["record"]["body"],
            crate::mcp::shape::fence(&crate::mcp::shape::truncate_string(&long, 100)),
            "{v}"
        );
        Ok(())
    }

    /// The page size bounds the failed list and nothing else: the three
    /// counts describe the whole spool on every page.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_page_size_never_moves_the_spool_counts() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        put(dir.path(), "p1.vcon.json", b"{}")?;
        put(dir.path(), "p2.vcon.json", b"{}")?;
        put(&dir.path().join("delivered"), "d1.vcon.json", b"{}")?;
        for name in ["f1.vcon.json", "f2.vcon.json", "f3.vcon.json"] {
            put(&dir.path().join("failed"), name, b"{}")?;
        }
        let server = empty_server().with_vcon_spool(dir.path());
        let one = spool_status(
            &server,
            VconSpoolStatusParams {
                limit: Some(1),
                ..VconSpoolStatusParams::default()
            },
        )
        .await?;
        let all = spool_status(&server, VconSpoolStatusParams::default()).await?;
        assert_eq!(one["returned"], 1, "premise: the page was cut: {one}");
        assert_eq!(all["returned"], 3, "premise: the page was whole: {all}");
        for key in ["pending", "delivered", "failed"] {
            assert_eq!(one[key], all[key], "{key} moved with the page size");
        }
        assert_eq!(one["failed"], 3, "{one}");
        Ok(())
    }

    /// A spool directory that does not exist yet answers zeros and says it
    /// does not exist, rather than failing: the capture writes it on its
    /// first container.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn a_spool_that_does_not_exist_answers_zeros_and_says_so() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let missing = dir.path().join("not-yet");
        let v = spool_status(
            &empty_server().with_vcon_spool(&missing),
            VconSpoolStatusParams::default(),
        )
        .await?;
        assert_eq!(v["spool"]["exists"], false, "{v}");
        assert_eq!(v["delivered_dir"]["exists"], false, "{v}");
        assert_eq!(v["pending"], 0, "{v}");
        assert_eq!(v["failed"], 0, "{v}");
        assert!(
            !missing.exists(),
            "the status tool must not create the spool"
        );
        Ok(())
    }

    /// A server that was not given a spool refuses, naming the flag.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn without_a_spool_the_status_names_the_flag() -> Result<(), TestError> {
        let err = empty_server()
            .vcon_spool_status(Parameters(VconSpoolStatusParams::default()))
            .await
            .err()
            .ok_or("no spool configured must be refused")?;
        assert_eq!(code_of(err.clone()), -32602);
        assert!(
            message_of(err).contains("--export-vcon-dir"),
            "the refusal names the flag that sets the spool"
        );
        Ok(())
    }

    // ── validate_vcon (RV6) ──────────────────────────────────────────

    /// A `validate_vcon` answer, parsed.
    #[cfg(feature = "vcon")]
    async fn validated(
        server: &SipnabMcp,
        params: ValidateVconParams,
    ) -> Result<serde_json::Value, TestError> {
        let result = server
            .validate_vcon(Parameters(params))
            .await
            .map_err(|e| format!("validation should answer: {e:?}"))?;
        payload(&result)
    }

    /// A container sipnab just exported passes the schema sipnab vendors.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn validate_vcon_passes_a_container_this_server_just_built() -> Result<(), TestError> {
        let v = validated(
            &server_with(&[("valid@x", 200)])?,
            ValidateVconParams {
                call_id: Some("valid@x".to_string()),
                ..ValidateVconParams::default()
            },
        )
        .await?;

        assert_eq!(v["verdict"], "valid", "{v}");
        assert!(v["errors"].as_array().is_some_and(Vec::is_empty), "{v}");
        assert_eq!(v["schema_version"], 2, "{v}");
        assert_eq!(
            v["call_id"], "valid@x",
            "the answer must name what it judged: {v}"
        );
        assert_eq!(
            v["schema_path"], "tests/schemas/vcon.schema.json",
            "and which schema it read: {v}"
        );
        Ok(())
    }

    /// RV6: a supplied container that breaks a rule is INVALID, and the
    /// finding says where. The rule here is one draft-ietf-vcon-vcon-core-04
    /// added: `parties` MUST NOT be present on a `transfer` Dialog Object
    /// (core-04 section 4.3.4).
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn validate_vcon_refuses_a_transfer_object_carrying_parties() -> Result<(), TestError> {
        let v = validated(
            &empty_server(),
            ValidateVconParams {
                container: Some(serde_json::json!({
                    "uuid": "018f3a2b-4c5d-8e6f-9012-3456789abcde",
                    "created_at": "2026-09-01T12:00:00Z",
                    "dialog": [{"type": "transfer", "parties": [0, 1]}],
                })),
                ..ValidateVconParams::default()
            },
        )
        .await?;

        assert_eq!(v["verdict"], "invalid", "{v}");
        assert_eq!(v["errors"][0]["instance_path"], "/dialog/0", "{v}");
        assert_eq!(v["errors"][0]["keyword"], "not", "{v}");
        assert!(
            v["errors"][0]["detail"]
                .as_str()
                .is_some_and(|d| d.contains("parties")),
            "the finding must name the member: {v}"
        );
        Ok(())
    }

    /// The core-03 empty Dialog Object is an ordinary error, and the response
    /// carries no deviation fields: core-04 left nothing to excuse.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn validate_vcon_reports_the_core_03_empty_dialog_object_as_an_error()
    -> Result<(), TestError> {
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
        .await?;

        assert_eq!(v["verdict"], "invalid", "{v}");
        assert_eq!(v["errors"][0]["instance_path"], "/dialog/0", "{v}");
        assert_eq!(v["errors"][0]["keyword"], "required", "{v}");
        for gone in ["deviations", "explanations"] {
            assert!(v.get(gone).is_none(), "{gone} left the shape: {v}");
        }
        Ok(())
    }

    /// Neither argument, and both arguments, are refused.
    #[tokio::test]
    async fn validate_vcon_refuses_a_request_naming_nothing_or_everything() -> Result<(), TestError>
    {
        let neither = empty_server()
            .validate_vcon(Parameters(ValidateVconParams::default()))
            .await
            .err()
            .ok_or("a request naming nothing must be refused")?;
        assert_eq!(code_of(neither), -32602);

        let both = empty_server()
            .validate_vcon(Parameters(ValidateVconParams {
                call_id: Some("a@x".to_string()),
                container: Some(serde_json::json!({})),
            }))
            .await
            .err()
            .ok_or("a request naming both must be refused")?;
        assert_eq!(code_of(both), -32602);
        Ok(())
    }

    /// A `container` that is not an object is refused, by name.
    ///
    /// The likely mistake is handing over the container as a STRING, which is
    /// what every surface here warns about in the other direction.
    #[tokio::test]
    async fn validate_vcon_refuses_a_container_that_is_not_an_object() -> Result<(), TestError> {
        let err = empty_server()
            .validate_vcon(Parameters(ValidateVconParams {
                container: Some(serde_json::json!("{\"uuid\":\"x\"}")),
                ..ValidateVconParams::default()
            }))
            .await
            .err()
            .ok_or("a string is not a container")?;
        assert_eq!(code_of(err), -32602);
        Ok(())
    }
}
