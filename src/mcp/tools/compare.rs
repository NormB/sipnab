// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tools whose subject is NOT the loaded capture.
//!
//! Every other tool on this surface answers about the dialogs this server is
//! holding. These two reach past them: `compare_captures` reads two files off
//! disk and diffs their aggregates, and `build_evidence_package` writes a
//! directory of artifacts that leaves the process entirely.
//!
//! That is what makes them one theme rather than two. Both cross the boundary
//! between "what sipnab knows" and "what is on the filesystem", so both are
//! confined to `--mcp-file-root` by the same resolver every file tool uses,
//! and neither may be reasoned about as though the answer described the
//! capture the agent has been asking about.

use crate::mcp::server::SipnabMcp;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};

/// Parameters for `compare_captures`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CompareCapturesParams {
    /// Baseline capture: a bare filename inside `--mcp-file-root`.
    pub a: String,
    /// Capture to hold against the baseline: a bare filename in the same root.
    pub b: String,
    /// Fields to diff, from the `aggregate_dialogs` vocabulary. Empty or
    /// omitted takes `state` and `response_code`.
    #[serde(default)]
    pub dimensions: Option<Vec<String>>,
    /// Rows per dimension. Everything past it is summed into `other`.
    #[serde(default)]
    pub top_n: Option<u32>,
}

/// Parameters for `build_evidence_package`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct BuildEvidencePackageParams {
    /// Call-IDs to package, in the order they should appear.
    pub call_ids: Vec<String>,
    /// Directory to create inside `--mcp-file-root`. A bare name, not a path,
    /// and it must not already exist.
    pub filename: String,
}

/// What reading one capture produced.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CaptureSide {
    /// The name the caller gave.
    pub filename: String,
    /// Packets read from the file.
    pub packets: u64,
    /// Dialogs the read produced.
    pub dialogs: usize,
    /// RTP streams the read produced.
    pub streams: usize,
    /// Dialogs the scratch store's capacity refused.
    ///
    /// Non-zero means this side is TRUNCATED and every count below it is a
    /// floor, not a total. Reported rather than hidden because a comparison
    /// against a partial population is a wrong answer that looks like a right
    /// one.
    pub dialogs_dropped: u64,
    /// Why the read stopped early, when it did. A truncated pcap is the normal
    /// state of a rotating capture's newest member, so a partial read is
    /// reported rather than refused — but the counts beside it are of what was
    /// readable, not of what the file holds.
    pub read_error: Option<String>,
}

/// One value's movement between the two captures.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct BucketDelta {
    /// The grouped value, rendered as a string. Absent from a side means zero
    /// there, not missing: a response code that appears only in `b` is the
    /// finding.
    pub value: String,
    /// Dialogs in this bucket in capture `a`.
    pub a: usize,
    /// Dialogs in this bucket in capture `b`.
    pub b: usize,
    /// `b - a`. Negative means the value became rarer.
    pub delta: i64,
}

/// One dimension's diff.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DimensionDiff {
    /// The field grouped on.
    pub dimension: String,
    /// Buckets, largest absolute movement first.
    pub buckets: Vec<BucketDelta>,
    /// Everything past `top_n`, summed, so the rows and the remainder account
    /// for the whole population on both sides.
    pub other: BucketDelta,
    /// Distinct values seen across both captures.
    pub distinct_values: usize,
}

/// Answer shape for `compare_captures`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CompareCapturesResponse {
    /// Response shape version.
    pub schema_version: u32,
    /// The baseline.
    pub a: CaptureSide,
    /// The capture held against it.
    pub b: CaptureSide,
    /// One entry per requested dimension, in the order requested.
    pub dimensions: Vec<DimensionDiff>,
    /// What the two sides are and what the numbers do not cover.
    pub summary: String,
}

/// Map the shared raw comparison onto the MCP wire shape, fencing the bucket
/// values of the sender-controlled dimensions before they reach a model.
///
/// Only `from.user`, `to.user`, `ua` and `rtp.codec` carry attacker-typed text;
/// a `state` or `response_code` bucket is sipnab's own vocabulary and is left
/// as-is. `fence_field`, matching `dialog_group_value`, which fences the same
/// four when a single-capture aggregate is rendered.
fn fence_comparison(cmp: crate::capture::compare::CaptureComparison) -> CompareCapturesResponse {
    fn to_side(s: crate::capture::compare::CaptureSide) -> CaptureSide {
        CaptureSide {
            filename: s.filename,
            packets: s.packets,
            dialogs: s.dialogs,
            streams: s.streams,
            dialogs_dropped: s.dialogs_dropped,
            read_error: s.read_error,
        }
    }
    let fenced = |dimension: &str, bd: &crate::capture::compare::BucketDelta| BucketDelta {
        value: if matches!(dimension, "from.user" | "to.user" | "ua" | "rtp.codec") {
            crate::mcp::shape::fence_field(&bd.value)
        } else {
            bd.value.clone()
        },
        a: bd.a,
        b: bd.b,
        delta: bd.delta,
    };
    let dimensions = cmp
        .dimensions
        .iter()
        .map(|dd| DimensionDiff {
            dimension: dd.dimension.clone(),
            buckets: dd
                .buckets
                .iter()
                .map(|b| fenced(&dd.dimension, b))
                .collect(),
            other: fenced(&dd.dimension, &dd.other),
            distinct_values: dd.distinct_values,
        })
        .collect();
    CompareCapturesResponse {
        schema_version: 1,
        a: to_side(cmp.a),
        b: to_side(cmp.b),
        dimensions,
        summary: cmp.summary,
    }
}

/// The payload block of a tool result — the one that is not the provenance
/// note.
///
/// `None` when the result carries no such block, which every caller here turns
/// into an internal error rather than writing an empty artifact: a ladder file
/// that exists and is blank is worse evidence than one that was never written.
fn payload_text(result: &CallToolResult) -> Option<String> {
    let note = crate::mcp::shape::untrusted_note();
    result
        .content
        .iter()
        .filter_map(|c| c.as_text())
        .map(|t| t.text.clone())
        .find(|t| *t != note)
}

/// The warning that has to travel WITH the package.
///
/// The directory is what gets attached to a ticket or forwarded to a carrier,
/// and whoever opens it there never saw the tool description. Restating the
/// rebuilt-frames disclaimer inside the artifact is the only place it
/// reaches that reader.
fn package_readme(package: &str, call_count: usize, files: &[String]) -> String {
    format!(
        "# sipnab evidence package\n\
         \n\
         Produced by sipnab {version} for {call_count} call(s).\n\
         \n\
         ## THE FRAMES IN `signaling.pcapng` WERE REBUILT, NOT COPIED\n\
         \n\
         sipnab retains parsed SIP messages rather than captured frames, so \
         each packet in that file is a synthetic Ethernet/IPv4/UDP frame \
         constructed around one message's bytes. The SIP layer is \
         byte-faithful; the link, IP and transport headers are reconstructed \
         from the addresses and ports sipnab recorded, and MAC addresses, IP \
         identification, checksums, fragmentation and TCP state are not what \
         was on the wire. A SIP-over-TCP message is written as UDP.\n\
         \n\
         Non-SIP traffic — RTP, RTCP, DNS, ICMP — is NOT in that file. Do not \
         read its packet count as a capture-level count. The RTP measurements \
         in this package were taken from the original capture and are not \
         reproducible from the pcapng alone.\n\
         \n\
         ## Untrusted content\n\
         \n\
         {note}\n\
         \n\
         ## Contents of `{package}`\n\
         \n\
         {listing}\n",
        version = env!("CARGO_PKG_VERSION"),
        note = crate::mcp::shape::untrusted_note(),
        listing = files
            .iter()
            .map(|f| format!("- `{f}`"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

#[tool_router(router = compare_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Diff the aggregates of two capture files in the file root.
    ///
    /// Neither side is the capture this server has loaded, and neither read
    /// touches its stores: both files are read into private stores that are
    /// dropped before the answer is built. What an agent asked about a minute
    /// ago is still true afterwards.
    ///
    /// The read runs on a blocking thread. Two whole captures inside a tool
    /// handler would otherwise hold the single runtime thread the MCP server
    /// and the REST API share — the failure [`crate::mcp::load`] documents.
    ///
    /// # What is not isolated
    ///
    /// The dialogs and streams are private to this call; the PROCESS-WIDE
    /// frame counters are not. Reading a file through the shared pipeline
    /// bumps the undecodable-frame tallies and the ICMP evidence store that
    /// `get_capture_report` reports, exactly as `open_capture` does — this is
    /// that behavior reused, not a new one. Hence `read_only_hint = false`:
    /// nothing is destroyed, but something observable moves.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `--mcp-file-root` is unset, when either
    /// name is not a bare filename inside it, when both names resolve to one
    /// file, or when a dimension is not groupable.
    ///
    /// `internal_error` (-32603) when the blocking read cannot be joined, or
    /// when a capture yielded no dialogs AND reported a read error — a diff
    /// against a file that would not open shows every bucket collapsing to
    /// zero, which is a finding that is not there.
    #[tool(
        name = "compare_captures",
        description = "Diffs two capture files in --mcp-file-root by aggregate: \
                       per dimension, how many dialogs fell in each bucket in \
                       each capture and how far that moved. Dimensions are the \
                       aggregate_dialogs vocabulary (state, response_code, \
                       method, from.user, to.user, ua, src.ip, dst.ip, \
                       rtp.codec), defaulting to state and response_code. \
                       Buckets are ranked by how much they MOVED, so 'today is \
                       worse than yesterday, and here is where' is the first \
                       row. Neither file becomes the loaded capture and no \
                       answer about the loaded capture changes.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn compare_captures(
        &self,
        Parameters(params): Parameters<CompareCapturesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // The vocabulary check, `since`-free read, ranking and summary are
        // shared with the REST route in `crate::capture::compare` — one rule in
        // one place. Vocabulary first, files second: reading two captures is
        // the most expensive thing this surface does, and a mistyped dimension
        // must not cost it. `resolve_dimensions` runs before any file is
        // touched.
        let dims = crate::capture::compare::resolve_dimensions(params.dimensions.as_deref())
            .map_err(|e| rmcp::ErrorData::invalid_params(e.to_string(), None))?;
        let top_n = crate::mcp::shape::resolve_limit_with_cap(params.top_n, self.row_cap);

        // The MCP resolver confines both names to `--mcp-file-root` and
        // canonicalizes them; the shared `compare` catches two names for one
        // file. A guard on `a` alone would let `b` walk out of the root.
        let path_a = self.resolve_in_root(&params.a)?;
        let path_b = self.resolve_in_root(&params.b)?;

        let (name_a, name_b) = (params.a.clone(), params.b.clone());
        let max_dialogs = crate::cli::Cli::DEFAULT_DIALOG_LIMIT as usize;
        let max_streams = crate::cli::Cli::DEFAULT_MAX_STREAMS as usize;
        // On a blocking thread: two whole captures inside a handler would hold
        // the single runtime thread the MCP server and the REST API share.
        let comparison = tokio::task::spawn_blocking(move || {
            crate::capture::compare::compare(
                crate::capture::compare::CaptureRef {
                    path: &path_a,
                    name: &name_a,
                },
                crate::capture::compare::CaptureRef {
                    path: &path_b,
                    name: &name_b,
                },
                &dims,
                max_dialogs,
                max_streams,
                top_n,
            )
        })
        .await
        .map_err(|e| {
            rmcp::ErrorData::internal_error(format!("the capture read did not finish: {e}"), None)
        })?
        .map_err(|e| match e {
            // A diff against a file that would not open shows every bucket
            // collapsing to zero, a finding that is not there — internal, not a
            // bad request. The other two are the caller's input.
            crate::capture::compare::CompareError::Unreadable { .. } => {
                rmcp::ErrorData::internal_error(e.to_string(), None)
            }
            crate::capture::compare::CompareError::SameFile { .. }
            | crate::capture::compare::CompareError::UnknownDimension { .. } => {
                rmcp::ErrorData::invalid_params(e.to_string(), None)
            }
        })?;

        let response = fence_comparison(comparison);
        Ok(CallToolResult::success(vec![
            ContentBlock::json(response)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }

    /// Write one directory holding everything an escalation needs for a set
    /// of calls.
    ///
    /// pcapng, a ladder and RTP stats per call, a manifest, and a README
    /// carrying the rebuilt-frames disclaimer. The disclaimer lives
    /// INSIDE the directory on purpose: the directory is what gets forwarded,
    /// and the person who opens it at the carrier never saw the tool that
    /// made it.
    ///
    /// The ladder and the stats come from `render_ladder` and `rtp_stats`
    /// rather than from a second rendering path, so a package can never
    /// disagree with what the same agent was shown over the wire.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `--mcp-file-root` is unset, when
    /// `filename` is not a bare name inside it, when that name is already
    /// taken or names a capture this server is reading, when `call_ids` is
    /// empty or longer than the row cap, or when a Call-ID is not in the
    /// store.
    ///
    /// `internal_error` (-32603) when a file cannot be written. The
    /// part-built directory is removed first, so a failed call leaves no
    /// package and no claimed name.
    #[tool(
        name = "build_evidence_package",
        description = "Writes one directory in --mcp-file-root holding \
                       everything an escalation needs for the named calls: \
                       signaling.pcapng, a markdown ladder and an RTP-stats \
                       JSON per call, a manifest, and a README stating that \
                       the pcapng's frames were REBUILT rather than copied. \
                       The directory must not already exist; sipnab never \
                       writes over a name that is taken. Use it to hand a call \
                       to a carrier or attach it to a ticket, instead of \
                       pasting tool output into a message.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub async fn build_evidence_package(
        &self,
        Parameters(params): Parameters<BuildEvidencePackageParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if params.call_ids.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "call_ids must name at least one call: an empty package is a \
                 directory of disclaimers"
                    .to_string(),
                None,
            ));
        }
        let cap = self.row_cap;
        if params.call_ids.len() > cap {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "{} call_ids exceeds this server's ceiling of {cap}; package \
                     them in batches",
                    params.call_ids.len()
                ),
                None,
            ));
        }
        // Deduped in the caller's order: a repeated Call-ID would otherwise
        // write the same ladder twice under two ordinals, and the manifest
        // would claim two calls where there is one.
        let mut call_ids: Vec<String> = Vec::with_capacity(params.call_ids.len());
        for id in &params.call_ids {
            if !call_ids.iter().any(|seen| seen == id) {
                call_ids.push(id.clone());
            }
        }

        // WRITES into the root: the same guard `export_capture` uses. It
        // refuses a path, a symlink out of the root, a capture this run is
        // reading, and any name already taken — including by a directory.
        let dir = self.resolve_in_root_for_write(&params.filename)?;

        // Every Call-ID checked, and the messages collected, BEFORE anything
        // is created. A package half-written around an unknown id leaves the
        // name claimed and the directory unusable.
        let messages: Vec<crate::sip::SipMessage> = {
            let ds = self.dialog_store.read();
            let mut collected = Vec::new();
            for id in &call_ids {
                let dialog = ds.get(id).ok_or_else(|| {
                    rmcp::ErrorData::invalid_params(format!("call_id '{id}' not found"), None)
                })?;
                collected.extend(dialog.messages.iter().cloned());
            }
            collected
        };
        if messages.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "the named calls hold no messages, so there is nothing to \
                 package"
                    .to_string(),
                None,
            ));
        }
        let mut messages = messages;
        // Chronological across the whole set, not per call: a multi-leg
        // escalation is read as one timeline, and a pcap grouped by leg hides
        // the interleaving that is usually the finding.
        crate::sort::sort_by_dyn(&mut messages, &mut |x, y| x.timestamp.cmp(&y.timestamp));

        // Ordinal filenames, never the Call-ID. A Call-ID is arbitrary
        // attacker-chosen text: it can hold a separator, a leading dash, a
        // NUL-adjacent byte or 400 characters, and none of that belongs in a
        // filename this tool constructs. The manifest maps ordinal to
        // Call-ID, which is where the correlation belongs.
        let mut artifacts: Vec<serde_json::Value> = Vec::with_capacity(call_ids.len());
        let mut files: Vec<String> = vec!["README.md".into(), "manifest.json".into()];
        let mut per_call: Vec<(String, String)> = Vec::new();
        for (i, id) in call_ids.iter().enumerate() {
            let ladder_name = format!("call-{:02}-ladder.md", i + 1);
            let rtp_name = format!("call-{:02}-rtp.json", i + 1);
            let ladder = self
                .render_ladder(Parameters(crate::mcp::server::RenderLadderParams {
                    call_id: id.clone(),
                    format: Some("markdown".to_string()),
                }))
                .await?;
            let ladder = payload_text(&ladder).ok_or_else(|| {
                rmcp::ErrorData::internal_error(
                    format!("render_ladder returned no report for '{id}'"),
                    None,
                )
            })?;
            let stats = self
                .rtp_stats(Parameters(crate::mcp::server::RtpStatsParams {
                    call_id: Some(id.clone()),
                    ..Default::default()
                }))
                .await?;
            let stats = payload_text(&stats).ok_or_else(|| {
                rmcp::ErrorData::internal_error(
                    format!("rtp_stats returned no payload for '{id}'"),
                    None,
                )
            })?;
            artifacts.push(serde_json::json!({
                "index": i + 1,
                // Verbatim, like every other Call-ID this surface returns:
                // it is an identifier the reader feeds back to another tool,
                // and the README's provenance note covers its origin.
                "call_id": id,
                "ladder": ladder_name,
                "rtp_stats": rtp_name,
            }));
            files.push(ladder_name.clone());
            files.push(rtp_name.clone());
            per_call.push((ladder_name, ladder));
            per_call.push((rtp_name, stats));
        }
        files.push("signaling.pcapng".to_string());

        // `create_dir`, not `create_dir_all`: the parent is the file root and
        // already exists, and an existing name must fail here too rather than
        // be adopted. That is a second line behind the resolver's check, not
        // a substitute for it.
        std::fs::create_dir(&dir).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("creating {}: {e}", dir.display()), None)
        })?;

        let write = |name: &str, body: &str| -> Result<(), rmcp::ErrorData> {
            std::fs::write(dir.join(name), body).map_err(|e| {
                // A part-built package must not survive: it would hold the
                // name against a retry and read as complete evidence.
                let _ = std::fs::remove_dir_all(&dir);
                rmcp::ErrorData::internal_error(format!("writing {name}: {e}"), None)
            })
        };
        for (name, body) in &per_call {
            write(name, body)?;
        }
        let manifest = serde_json::json!({
            "schema_version": 1,
            "sipnab_version": env!("CARGO_PKG_VERSION"),
            "package": params.filename,
            "signaling": "signaling.pcapng",
            "signaling_frames_rebuilt": true,
            "calls": artifacts,
        });
        write("manifest.json", &format!("{manifest:#}"))?;
        write(
            "README.md",
            &package_readme(&params.filename, call_ids.len(), &files),
        )?;

        let pcap = dir.join("signaling.pcapng");
        let written =
            crate::mcp::server::write_messages_to_pcap(&messages, &pcap).map_err(|e| {
                let _ = std::fs::remove_dir_all(&dir);
                rmcp::ErrorData::internal_error(format!("writing {}: {e}", pcap.display()), None)
            })?;

        tracing::info!(
            "MCP build_evidence_package wrote {} call(s) and {written} message(s) to {}",
            call_ids.len(),
            dir.display()
        );
        Ok(CallToolResult::success(vec![
            ContentBlock::json(serde_json::json!({
                "schema_version": 1,
                "path": dir.display().to_string(),
                "calls": call_ids.len(),
                "messages": written,
                "files": files,
                "summary": format!(
                    "{} call(s) packaged in {}. README.md inside it states that \
                     the frames in signaling.pcapng were rebuilt from parsed \
                     messages rather than copied, which is the claim the \
                     recipient has to see.",
                    call_ids.len(),
                    dir.display()
                ),
            }))?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }
}

/// Unit tests for the two tools that reach outside the loaded capture, driven
/// directly (no transport).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    use parking_lot::RwLock;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    /// A fixture shipped in `tests/pcap-samples/`.
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples")
            .join(name)
    }

    /// A temp directory holding copies of `names` from `tests/pcap-samples/`.
    ///
    /// Named per test rather than shared: two tests writing one root would
    /// each see the other's leftovers, and the name-already-taken rule these
    /// tests exercise would then depend on execution order.
    fn root_with(tag: &str, names: &[&str]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("sipnab-cmp-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the file root");
        for name in names {
            std::fs::copy(fixture(name), root.join(name)).expect("stage a fixture");
        }
        root
    }

    /// A server over empty stores.
    fn empty_server() -> SipnabMcp {
        SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(1000, false))),
            Arc::new(RwLock::new(StreamStore::new(1000))),
        )
    }

    /// A server whose stores hold a real capture, read through the same path
    /// `open_capture` uses.
    fn server_from_fixture(name: &str) -> SipnabMcp {
        let ds = Arc::new(RwLock::new(DialogStore::new(1000, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(1000)));
        let progress = AtomicU64::new(0);
        crate::mcp::load::read_into_stores(&fixture(name), &ds, &ss, &progress)
            .expect("the fixture must read cleanly");
        SipnabMcp::new(ds, ss)
    }

    /// A server holding one dialog whose Call-ID is `call_id`, verbatim.
    fn server_with_call_id(call_id: &str) -> SipnabMcp {
        let raw = crate::test_utils::build_sip_message(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let ts = chrono::DateTime::from_timestamp(1_718_000_000, 0).expect("a valid timestamp");
        let msg = crate::sip::parser::parse_sip(
            &raw,
            ts,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("the fixture INVITE must parse");
        let mut ds = DialogStore::new(1000, false);
        ds.process_message(msg);
        SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(StreamStore::new(1000))),
        )
    }

    /// The payload block of a result, as parsed JSON.
    fn json_of(result: &CallToolResult) -> serde_json::Value {
        let text = payload_text(result).expect("a payload block");
        serde_json::from_str(&text).expect("the payload must be JSON")
    }

    /// Dialogs and their `state` tally for one fixture, computed here rather
    /// than taken from the tool, so the tool's numbers are checked against an
    /// INDEPENDENT read of the same file — reimplemented here on purpose rather
    /// than routed through `crate::capture::compare`, so the cross-check does
    /// not lean on the code it is checking.
    fn states_of(name: &str) -> (usize, std::collections::BTreeMap<String, usize>) {
        let ds = Arc::new(RwLock::new(DialogStore::new(1000, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(1000)));
        let progress = AtomicU64::new(0);
        crate::mcp::load::read_into_stores(&fixture(name), &ds, &ss, &progress)
            .expect("the fixture must read cleanly");
        let dsr = ds.read();
        let ssr = ss.read();
        let mut tally: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for d in dsr.iter() {
            let streams: Vec<&crate::rtp::stream::RtpStream> =
                ssr.streams_for(&d.call_id).collect();
            if let Some(v) = crate::sip::dialog::dialog_group_value_raw("state", d, &streams) {
                *tally.entry(v).or_insert(0) += 1;
            }
        }
        (dsr.len(), tally)
    }

    // ── compare_captures ────────────────────────────────────────────────

    /// Without `--mcp-file-root` the tool refuses and names the flag, so an
    /// agent learns what to ask the operator for.
    #[tokio::test]
    async fn compare_captures_needs_a_file_root() {
        let err = empty_server()
            .compare_captures(Parameters(CompareCapturesParams {
                a: "yesterday.pcap".into(),
                b: "today.pcap".into(),
                ..Default::default()
            }))
            .await
            .expect_err("must refuse without a root");
        assert!(
            err.message.contains("--mcp-file-root"),
            "the refusal must name the flag; got {err:?}"
        );
    }

    /// A traversal is refused for what it is, by the same resolver every other
    /// file tool uses. Both sides are checked: a guard on `a` alone would let
    /// `b` walk out of the root.
    #[tokio::test]
    async fn compare_captures_refuses_a_path_traversal() {
        let root = root_with("traversal", &["sip-rtp-g711.pcap"]);
        let server = empty_server().with_file_root(&root);
        for (a, b) in [
            ("../escape.pcap", "sip-rtp-g711.pcap"),
            ("sip-rtp-g711.pcap", "../escape.pcap"),
            ("/etc/passwd", "sip-rtp-g711.pcap"),
            ("sub/dir.pcap", "sip-rtp-g711.pcap"),
        ] {
            let err = server
                .compare_captures(Parameters(CompareCapturesParams {
                    a: a.into(),
                    b: b.into(),
                    ..Default::default()
                }))
                .await
                .expect_err("must refuse a path");
            assert!(
                err.message.contains("bare filename") || err.message.contains("resolves outside"),
                "'{a}' vs '{b}' must be refused for what it is; got {err:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The dimension check runs BEFORE either file is touched. Reading two
    /// captures is the most expensive call on this surface and a typo must not
    /// cost it — proved by naming files that do not exist and still getting
    /// the dimension error.
    #[tokio::test]
    async fn compare_captures_checks_dimensions_before_reading_anything() {
        let root = root_with("dimension", &[]);
        let err = empty_server()
            .with_file_root(&root)
            .compare_captures(Parameters(CompareCapturesParams {
                a: "absent-a.pcap".into(),
                b: "absent-b.pcap".into(),
                dimensions: Some(vec!["hour".into()]),
                ..Default::default()
            }))
            .await
            .expect_err("must refuse an ungroupable dimension");
        assert!(
            err.message.contains("cannot compare on 'hour'"),
            "the refusal must name the dimension, not the missing file; got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Two names for one file are refused. The comparison would be all zeros,
    /// which reads as "nothing changed" rather than "you asked nothing".
    #[tokio::test]
    async fn compare_captures_refuses_a_capture_against_itself() {
        let root = root_with("selfdiff", &["sip-rtp-g711.pcap"]);
        let err = empty_server()
            .with_file_root(&root)
            .compare_captures(Parameters(CompareCapturesParams {
                a: "sip-rtp-g711.pcap".into(),
                b: "sip-rtp-g711.pcap".into(),
                ..Default::default()
            }))
            .await
            .expect_err("must refuse a self comparison");
        assert!(
            err.message.contains("same file"),
            "the refusal must say why; got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The counts describe the two files, and each side's `state` buckets sum
    /// to that side's dialogs. Checked against an independent read of each
    /// fixture, so reading one file twice — or crossing the two sides — is
    /// visible rather than plausible.
    #[tokio::test]
    async fn compare_captures_reports_each_capture_separately() {
        let root = root_with("counts", &["sip-rtp-g711.pcap", "sip-auth-failure.pcapng"]);
        let (dialogs_a, states_a) = states_of("sip-rtp-g711.pcap");
        let (dialogs_b, states_b) = states_of("sip-auth-failure.pcapng");
        assert!(
            dialogs_a > 0 && dialogs_b > 0,
            "both fixtures must hold dialogs for this test to mean anything"
        );

        let result = empty_server()
            .with_file_root(&root)
            .compare_captures(Parameters(CompareCapturesParams {
                a: "sip-rtp-g711.pcap".into(),
                b: "sip-auth-failure.pcapng".into(),
                dimensions: Some(vec!["state".into()]),
                ..Default::default()
            }))
            .await
            .expect("the comparison should succeed");
        let v = json_of(&result);

        assert_eq!(v["a"]["dialogs"], dialogs_a, "side a must describe file a");
        assert_eq!(v["b"]["dialogs"], dialogs_b, "side b must describe file b");
        assert_eq!(v["a"]["filename"], "sip-rtp-g711.pcap");
        assert_eq!(v["b"]["filename"], "sip-auth-failure.pcapng");

        let buckets = v["dimensions"][0]["buckets"]
            .as_array()
            .expect("state buckets");
        let (mut sum_a, mut sum_b) = (0usize, 0usize);
        for bucket in buckets {
            let value = bucket["value"].as_str().expect("a bucket value");
            let (ca, cb) = (
                bucket["a"].as_u64().expect("a count") as usize,
                bucket["b"].as_u64().expect("b count") as usize,
            );
            assert_eq!(
                ca,
                states_a.get(value).copied().unwrap_or(0),
                "bucket '{value}' must carry file a's own count"
            );
            assert_eq!(
                cb,
                states_b.get(value).copied().unwrap_or(0),
                "bucket '{value}' must carry file b's own count"
            );
            assert_eq!(
                bucket["delta"].as_i64().expect("a delta"),
                cb as i64 - ca as i64,
                "delta must be b minus a"
            );
            sum_a += ca;
            sum_b += cb;
        }
        let other = &v["dimensions"][0]["other"];
        sum_a += other["a"].as_u64().unwrap_or(0) as usize;
        sum_b += other["b"].as_u64().unwrap_or(0) as usize;
        assert_eq!(sum_a, dialogs_a, "buckets plus other must account for a");
        assert_eq!(sum_b, dialogs_b, "buckets plus other must account for b");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Neither file becomes the loaded capture. Every answer the agent already
    /// has must still be true afterwards, which means the stores must hold
    /// exactly what they held.
    #[tokio::test]
    async fn compare_captures_leaves_the_loaded_capture_untouched() {
        let root = root_with(
            "untouched",
            &["sip-rtp-g711.pcap", "sip-auth-failure.pcapng"],
        );
        let server = server_from_fixture("sip-problem-call.pcap").with_file_root(&root);
        let before: Vec<String> = server
            .dialog_store
            .read()
            .iter()
            .map(|d| d.call_id.clone())
            .collect();
        assert!(!before.is_empty(), "the loaded capture must hold dialogs");

        server
            .compare_captures(Parameters(CompareCapturesParams {
                a: "sip-rtp-g711.pcap".into(),
                b: "sip-auth-failure.pcapng".into(),
                ..Default::default()
            }))
            .await
            .expect("the comparison should succeed");

        let after: Vec<String> = server
            .dialog_store
            .read()
            .iter()
            .map(|d| d.call_id.clone())
            .collect();
        assert_eq!(
            before, after,
            "comparing two files must not add, drop or reorder a loaded dialog"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A file that yields nothing and reports why is refused rather than
    /// diffed: every bucket would appear to have collapsed to zero, which is a
    /// finding that is not there.
    #[tokio::test]
    async fn compare_captures_refuses_a_file_that_would_not_read() {
        let root = root_with("unreadable", &["sip-rtp-g711.pcap"]);
        std::fs::write(root.join("notes.pcap"), b"this is not a capture\n")
            .expect("stage a non-capture");
        let err = empty_server()
            .with_file_root(&root)
            .compare_captures(Parameters(CompareCapturesParams {
                a: "sip-rtp-g711.pcap".into(),
                b: "notes.pcap".into(),
                ..Default::default()
            }))
            .await
            .expect_err("must refuse a file that yielded nothing");
        assert!(
            err.message.contains("notes.pcap") && err.message.contains("no dialogs"),
            "the refusal must name the file and why; got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── build_evidence_package ──────────────────────────────────────────

    /// Without `--mcp-file-root` the tool refuses and names the flag — the
    /// same gate `export_capture` applies, not a rule of its own.
    #[tokio::test]
    async fn build_evidence_package_needs_a_file_root() {
        let server = server_from_fixture("sip-rtp-g711.pcap");
        let call_id = server
            .dialog_store
            .read()
            .iter()
            .next()
            .map(|d| d.call_id.clone())
            .expect("the fixture must hold a dialog");
        let err = server
            .build_evidence_package(Parameters(BuildEvidencePackageParams {
                call_ids: vec![call_id],
                filename: "evidence".into(),
            }))
            .await
            .expect_err("must refuse without a root");
        assert!(
            err.message.contains("--mcp-file-root"),
            "the refusal must name the flag; got {err:?}"
        );
    }

    /// A traversal is refused and NOTHING is created outside the root. The
    /// assertion is on the filesystem, not on the message: a tool that refused
    /// with the right words and still wrote the directory would pass a
    /// message-only test.
    #[tokio::test]
    async fn build_evidence_package_refuses_a_path_traversal() {
        let root = root_with("pkg-traversal", &[]);
        let outside = root.join("..").join("sipnab-cmp-escape-package");
        let _ = std::fs::remove_dir_all(&outside);
        let server = server_from_fixture("sip-rtp-g711.pcap").with_file_root(&root);
        let call_id = server
            .dialog_store
            .read()
            .iter()
            .next()
            .map(|d| d.call_id.clone())
            .expect("the fixture must hold a dialog");

        for bad in [
            "../sipnab-cmp-escape-package",
            "/tmp/sipnab-cmp-escape-package",
            "sub/dir",
            "..",
        ] {
            let err = server
                .build_evidence_package(Parameters(BuildEvidencePackageParams {
                    call_ids: vec![call_id.clone()],
                    filename: bad.to_string(),
                }))
                .await
                .expect_err("must refuse a path");
            assert!(
                err.message.contains("bare filename") || err.message.contains("resolves outside"),
                "'{bad}' must be refused for what it is; got {err:?}"
            );
        }
        assert!(
            !outside.exists(),
            "a refused traversal must leave nothing at {}",
            outside.display()
        );
        assert_eq!(
            std::fs::read_dir(&root).expect("read the root").count(),
            0,
            "a refused traversal must leave nothing in the root either"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A symlink inside the root that points out of it is refused too: the
    /// escape is not in the string, and the kernel would follow it at `open`.
    #[cfg(unix)]
    #[tokio::test]
    async fn build_evidence_package_refuses_a_symlink_out_of_the_root() {
        let root = root_with("pkg-symlink", &[]);
        let outside =
            std::env::temp_dir().join(format!("sipnab-cmp-symlink-target-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).expect("create the target directory");
        std::os::unix::fs::symlink(&outside, root.join("evidence")).expect("stage the symlink");

        let server = server_from_fixture("sip-rtp-g711.pcap").with_file_root(&root);
        let call_id = server
            .dialog_store
            .read()
            .iter()
            .next()
            .map(|d| d.call_id.clone())
            .expect("the fixture must hold a dialog");
        let err = server
            .build_evidence_package(Parameters(BuildEvidencePackageParams {
                call_ids: vec![call_id],
                filename: "evidence".into(),
            }))
            .await
            .expect_err("must refuse a symlink out of the root");
        assert!(
            err.message.contains("resolves outside") || err.message.contains("already exists"),
            "the refusal must be about the link; got {err:?}"
        );
        assert_eq!(
            std::fs::read_dir(&outside)
                .expect("read the target")
                .count(),
            0,
            "nothing may be written through the link"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A name already taken is refused rather than written over: that file may
    /// be the only copy of a capture.
    #[tokio::test]
    async fn build_evidence_package_refuses_a_name_already_taken() {
        let root = root_with("pkg-taken", &[]);
        std::fs::create_dir(root.join("evidence")).expect("stage the collision");
        let server = server_from_fixture("sip-rtp-g711.pcap").with_file_root(&root);
        let call_id = server
            .dialog_store
            .read()
            .iter()
            .next()
            .map(|d| d.call_id.clone())
            .expect("the fixture must hold a dialog");
        let err = server
            .build_evidence_package(Parameters(BuildEvidencePackageParams {
                call_ids: vec![call_id],
                filename: "evidence".into(),
            }))
            .await
            .expect_err("must refuse a taken name");
        assert!(
            err.message.contains("already exists"),
            "the refusal must say the name is taken; got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty request is refused: a package of nothing is a directory of
    /// disclaimers.
    #[tokio::test]
    async fn build_evidence_package_refuses_an_empty_call_list() {
        let root = root_with("pkg-empty", &[]);
        let err = empty_server()
            .with_file_root(&root)
            .build_evidence_package(Parameters(BuildEvidencePackageParams {
                call_ids: Vec::new(),
                filename: "evidence".into(),
            }))
            .await
            .expect_err("must refuse an empty package");
        assert!(
            err.message.contains("at least one call"),
            "the refusal must say what is missing; got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An unknown Call-ID is caught BEFORE anything is created, so a bad
    /// request leaves no half-package holding the name against a retry.
    #[tokio::test]
    async fn an_unknown_call_id_leaves_no_directory_behind() {
        let root = root_with("pkg-unknown", &[]);
        let server = server_from_fixture("sip-rtp-g711.pcap").with_file_root(&root);
        let known = server
            .dialog_store
            .read()
            .iter()
            .next()
            .map(|d| d.call_id.clone())
            .expect("the fixture must hold a dialog");
        let err = server
            .build_evidence_package(Parameters(BuildEvidencePackageParams {
                call_ids: vec![known, "no-such-call@example.com".into()],
                filename: "evidence".into(),
            }))
            .await
            .expect_err("must refuse an unknown call");
        assert!(
            err.message.contains("no-such-call@example.com"),
            "the refusal must name the call; got {err:?}"
        );
        assert!(
            !root.join("evidence").exists(),
            "a refused package must not exist on disk"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The package holds the pcapng, a ladder and RTP stats per call, a
    /// manifest, and a README carrying the rebuilt-frames disclaimer. The
    /// disclaimer is the point: the directory is what gets forwarded, and the
    /// person who opens it never saw the tool description.
    #[tokio::test]
    async fn a_package_carries_the_artifacts_and_the_disclaimer() {
        let root = root_with("pkg-contents", &[]);
        let server = server_from_fixture("sip-rtp-g711.pcap").with_file_root(&root);
        let call_id = server
            .dialog_store
            .read()
            .iter()
            .next()
            .map(|d| d.call_id.clone())
            .expect("the fixture must hold a dialog");

        let result = server
            .build_evidence_package(Parameters(BuildEvidencePackageParams {
                call_ids: vec![call_id.clone()],
                filename: "evidence".into(),
            }))
            .await
            .expect("the package should be written");
        let v = json_of(&result);
        assert_eq!(v["calls"], 1);

        let dir = root.join("evidence");
        for name in [
            "README.md",
            "manifest.json",
            "signaling.pcapng",
            "call-01-ladder.md",
            "call-01-rtp.json",
        ] {
            let path = dir.join(name);
            let meta = std::fs::metadata(&path)
                .unwrap_or_else(|e| panic!("{} must exist: {e}", path.display()));
            assert!(meta.len() > 0, "{name} must not be empty");
        }

        let readme = std::fs::read_to_string(dir.join("README.md")).expect("read the README");
        assert!(
            readme.contains("REBUILT, NOT COPIED"),
            "the README must state that the frames were rebuilt; got:\n{readme}"
        );
        assert!(
            readme.contains("signaling.pcapng"),
            "the disclaimer must name the file it is about"
        );

        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("manifest.json")).expect("read"),
        )
        .expect("the manifest must be JSON");
        assert_eq!(manifest["calls"][0]["call_id"], call_id.as_str());
        assert_eq!(manifest["calls"][0]["ladder"], "call-01-ladder.md");
        assert_eq!(manifest["signaling_frames_rebuilt"], true);

        // The ladder must be the one `render_ladder` produces, not a second
        // rendering that could disagree with what the agent was shown.
        let ladder = std::fs::read_to_string(dir.join("call-01-ladder.md")).expect("read");
        let over_the_wire = server
            .render_ladder(Parameters(crate::mcp::server::RenderLadderParams {
                call_id: call_id.clone(),
                format: Some("markdown".into()),
            }))
            .await
            .expect("render_ladder should succeed");
        assert_eq!(
            ladder,
            payload_text(&over_the_wire).expect("a ladder"),
            "the packaged ladder must be byte-identical to the tool's"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Filenames are ordinals, never the Call-ID. A Call-ID is arbitrary
    /// sender-chosen text; one shaped like a path must not steer where a byte
    /// lands.
    #[tokio::test]
    async fn a_call_id_shaped_like_a_path_never_becomes_a_filename() {
        let root = root_with("pkg-evilid", &[]);
        let evil = "../../escaped/a b c.md";
        let server = server_with_call_id(evil).with_file_root(&root);
        server
            .build_evidence_package(Parameters(BuildEvidencePackageParams {
                call_ids: vec![evil.to_string()],
                filename: "evidence".into(),
            }))
            .await
            .expect("a hostile Call-ID must be packaged, not refused");

        let dir = root.join("evidence");
        let names: Vec<String> = std::fs::read_dir(&dir)
            .expect("read the package")
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert!(
            names
                .iter()
                .all(|n| !n.contains("escaped") && !n.contains("..")),
            "no file may be named after the Call-ID; got {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "call-01-ladder.md"),
            "the ladder must be filed under its ordinal; got {names:?}"
        );
        assert!(
            !root.join("escaped").exists() && !dir.join("escaped").exists(),
            "nothing may be created along the Call-ID's path"
        );
        // The manifest is where the correlation lives, verbatim.
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("manifest.json")).expect("read"),
        )
        .expect("the manifest must be JSON");
        assert_eq!(manifest["calls"][0]["call_id"], evil);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A Call-ID named twice is packaged once: two ordinals for one call would
    /// make the manifest claim two calls where there is one.
    #[tokio::test]
    async fn a_repeated_call_id_is_packaged_once() {
        let root = root_with("pkg-dedupe", &[]);
        let server = server_from_fixture("sip-rtp-g711.pcap").with_file_root(&root);
        let call_id = server
            .dialog_store
            .read()
            .iter()
            .next()
            .map(|d| d.call_id.clone())
            .expect("the fixture must hold a dialog");
        let result = server
            .build_evidence_package(Parameters(BuildEvidencePackageParams {
                call_ids: vec![call_id.clone(), call_id],
                filename: "evidence".into(),
            }))
            .await
            .expect("the package should be written");
        assert_eq!(json_of(&result)["calls"], 1, "the repeat must collapse");
        assert!(
            !root.join("evidence").join("call-02-ladder.md").exists(),
            "a second ordinal must not exist for one call"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
