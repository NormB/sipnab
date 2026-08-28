//! Artifacts that leave sipnab and run somewhere else.
//!
//! Every other tool group answers a question inside this process. These four
//! produce something that executes in another one: a gate CI runs on every
//! commit, a scenario SIPp replays, a filter Wireshark applies, a rule fail2ban
//! enforces.
//!
//! That is one theme rather than two. An analysis ending in a paragraph creates
//! work — somebody has to translate it into an action in a different tool. An
//! analysis ending in an artifact removes that step, and handing off cleanly to
//! the operator's own tooling is a deliberate position: sipnab is not trying to
//! own the workflow.
//!
//! # What is deliberately not here
//!
//! Config-fix generation — OpenSIPS or Kamailio route snippets. A test artifact
//! is inert; a route block that lands in a production proxy is a different
//! liability class, and the first time an agent-authored one drops calls it is
//! this project's name on it.

use crate::expect::{ExpectRule, Inputs, RuleError, Suite, evaluate};
use crate::mcp::server::SipnabMcp;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_router};
use serde::{Deserialize, Serialize};

/// Parameters for `evaluate_expectations`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct EvaluateExpectationsParams {
    /// The rules, inline. Mutually exclusive with `rules_toml`.
    #[serde(default)]
    pub rules: Option<Vec<ExpectRule>>,
    /// The verbatim text of a `sipnab.expect.toml`. Mutually exclusive with
    /// `rules`.
    ///
    /// The point of accepting the file's own bytes is that the agent then
    /// judges the capture against exactly what CI judges it against, rather
    /// than against its own transcription of it.
    #[serde(default)]
    pub rules_toml: Option<String>,
    /// A lint suppression file in `--mcp-file-root` to apply to the
    /// `lint_errors` rules. Omitted discovers a `.sipnablint` beside the
    /// capture, the same way `lint_dialog` does.
    #[serde(default)]
    pub suppression_file: Option<String>,
}

/// Parameters for `generate_repro`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct GenerateReproParams {
    /// The call to build a scenario from.
    pub call_id: String,
    /// Output format. `sipp` is the only one, and the default.
    #[serde(default)]
    pub format: Option<String>,
    /// Aspects of the captured request to hold byte-identical, because they
    /// are believed to have caused the outcome: `sdp`, `user_agent`, `headers`,
    /// `request_uri`, `cseq`, `call_id`, `tags`, `branch`.
    #[serde(default)]
    pub pin: Option<Vec<String>>,
    /// Aspects SIPp regenerates per run so the replay is a NEW call rather than
    /// a retransmission of the captured one: `call_id`, `tags`, `branch`.
    /// Defaults to all three.
    #[serde(default)]
    pub vary: Option<Vec<String>>,
    /// Optional bare filename in `--mcp-file-root` to also write the scenario
    /// to. The scenario text is returned either way.
    #[serde(default)]
    pub filename: Option<String>,
}

/// Parameters for `generate_wireshark_filter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct GenerateWiresharkFilterParams {
    /// The call the filter should select.
    pub call_id: String,
    /// Whether to include the call's RTP streams by SSRC. Defaults to true.
    #[serde(default)]
    pub include_media: Option<bool>,
}

/// Parameters for `generate_fail2ban_rule`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct GenerateFail2banRuleParams {
    /// The finding to build a rule from, spelled
    /// `<rule_name>@<src_ip>@<timestamp>` — the three fields
    /// `security_findings` already returns for every finding.
    pub finding_id: String,
}

/// Every aspect of a captured request `generate_repro` recognizes.
///
/// Listed once and read by the validator, the refusal message and the
/// hypothesis block, so an aspect cannot be accepted without being offered or
/// offered without being handled.
const REPRO_ASPECTS: &[&str] = &[
    "branch",
    "call_id",
    "cseq",
    "headers",
    "request_uri",
    "sdp",
    "tags",
    "user_agent",
];

/// The aspects SIPp can regenerate per run.
///
/// A strict subset of [`REPRO_ASPECTS`], and the reason is that "vary" needs a
/// generator, not just an opinion. SIPp supplies a fresh Call-ID, tag and
/// branch for every call it places; it has no defined way to invent a plausible
/// SDP body or User-Agent, and a scenario built on an invented one would
/// reproduce — or fail to — for a reason nobody chose.
const VARIABLE_ASPECTS: &[&str] = &["branch", "call_id", "tags"];

/// The identity aspects varied unless the caller says otherwise.
///
/// Replaying a captured Call-ID, tag and branch at a proxy is not a repro: to
/// the transaction layer it is a retransmission of a call it has already
/// answered, so the response says more about the proxy's transaction state than
/// about the theory under test.
const DEFAULT_VARY: &[&str] = &["call_id", "tags", "branch"];

/// Headers the scenario always supplies itself, whatever the capture held.
///
/// Routing and framing: a replay runs from a different host, so a captured Via
/// or Contact would send the responses to a machine that is not the one running
/// the test, and a captured Content-Length would contradict the body actually
/// sent. `User-Agent` is here because it is its own pinnable aspect.
const SCENARIO_OWNED_HEADERS: &[&str] = &[
    "call-id",
    "contact",
    "content-length",
    "content-type",
    "cseq",
    "from",
    "max-forwards",
    "record-route",
    "route",
    "to",
    "user-agent",
    "via",
];

#[tool_router(router = expectations_router, vis = "pub(crate)")]
impl SipnabMcp {
    /// Judge the capture against a set of expectations and return a verdict.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when neither or both of `rules` and
    /// `rules_toml` are given, when `rules_toml` does not parse, when a rule
    /// names a metric, scope or setting the evaluator does not accept, or when
    /// `suppression_file` cannot be resolved inside `--mcp-file-root`.
    #[tool(
        name = "evaluate_expectations",
        description = "Judges the loaded capture against a list of rules and \
                       returns a pass/fail verdict per rule plus an exit code \
                       for a build. A rule is {metric, op, value} with an \
                       optional scope, min_sample and grounded_only. Metrics: \
                       count (dialogs matching the scope), asr (answered over \
                       seized, as a RATIO from 0.0 to 1.0), lint_errors \
                       (conformance findings at or above a severity floor), and \
                       mos_p<N> (a percentile of estimated MOS, mos_p0 worst to \
                       mos_p100 best). Scopes are 'filter:<alias-or-DSL>' or \
                       'severity:<info|notice|warning|error>'. A rule whose \
                       population is empty FAILS as unevaluable rather than \
                       passing quietly; declaring min_sample is the only way to \
                       have a thin population reported as skipped instead. A \
                       suite whose every rule skipped reports the verdict \
                       not_evaluated with exit code 2, distinct from a pass. \
                       Rules arrive either as a JSON array or as the verbatim \
                       text of a sipnab.expect.toml file.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn evaluate_expectations(
        &self,
        Parameters(params): Parameters<EvaluateExpectationsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let rules: Vec<ExpectRule> = match (params.rules, params.rules_toml.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(rmcp::ErrorData::invalid_params(
                    "give either 'rules' or 'rules_toml', not both: two suites \
                     in one call have no defined order and the answer would not \
                     say which one was judged"
                        .to_string(),
                    None,
                ));
            }
            (None, None) => {
                return Err(rmcp::ErrorData::invalid_params(
                    "no expectations were given. Pass 'rules' as a JSON array, \
                     or 'rules_toml' as the text of a sipnab.expect.toml. A \
                     call with neither would report a verdict on nothing."
                        .to_string(),
                    None,
                ));
            }
            (Some(rules), None) => rules,
            (None, Some(text)) => {
                Suite::from_toml_str(text)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("rules_toml does not parse: {e}"),
                            None,
                        )
                    })?
                    .rules
            }
        };

        // Resolved before any lock: reading a suppression file touches the
        // filesystem, and holding the stores across it would block every other
        // tool for the duration of a disk read.
        let suppressions = self.resolve_suppressions(params.suppression_file.as_ref())?;

        let (report, capture_identity) = {
            // Capture, dialogs, streams — the order `CaptureState` documents.
            // Held together for the whole evaluation so every rule judges ONE
            // revision of the capture and the identity stamped on the verdict
            // names it.
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let capture_identity = state.identity.etag(ds.generation(), ss.generation());
            let report = evaluate(
                &rules,
                &Inputs {
                    dialogs: &ds,
                    streams: &ss,
                    thresholds: &self.alias_thresholds,
                    suppressions: suppressions.as_ref(),
                },
            );
            drop(ss);
            drop(ds);
            drop(state);
            (report, capture_identity)
        };

        let report = report.map_err(|e| match e {
            // Every variant is a defect in the rules the caller supplied, so
            // every one is -32602 rather than an internal error.
            RuleError::NoRules
            | RuleError::UnknownMetric { .. }
            | RuleError::UnknownScopeKind { .. }
            | RuleError::BadFilter { .. }
            | RuleError::UnknownSeverity { .. }
            | RuleError::SeverityScopeOnNonLintMetric { .. }
            | RuleError::GroundedOnlyOnNonMosMetric { .. }
            | RuleError::PercentileOutOfRange { .. } => {
                rmcp::ErrorData::invalid_params(e.to_string(), None)
            }
        })?;

        let mut payload = serde_json::to_value(report)
            .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "capture_identity".to_string(),
                serde_json::to_value(capture_identity)
                    .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?,
            );
        }
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Build a SIPp scenario that re-runs one call, encoding a hypothesis.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown `call_id`, a call holding no
    /// request to replay, an unknown `format`, an unknown aspect in `pin` or
    /// `vary`, an aspect named in both, an aspect in `vary` that SIPp cannot
    /// regenerate, a pinned SDP body that is not valid UTF-8, or a `filename`
    /// that does not resolve to a writable name inside `--mcp-file-root`.
    #[tool(
        name = "generate_repro",
        description = "Builds a SIPp scenario that replays one call, and takes \
                       the hypothesis as input: 'pin' names the aspects of the \
                       captured request believed to have caused the outcome and \
                       copies them byte-for-byte, 'vary' names the identity \
                       fields SIPp regenerates per run so the replay is a new \
                       call rather than a retransmission. Anything unpinned is \
                       replaced by a generic value, so a scenario with an empty \
                       pin list tests no theory and the response says so. The \
                       recv sequence asserts the responses the capture actually \
                       held, so running it either reproduces the outcome or \
                       reports the message that differed. Returns the scenario \
                       text, the pinned/varied/generated/omitted split, and the \
                       caveats that apply; writes the file too when 'filename' \
                       is given. Header values and SDP come from the packet's \
                       sender.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn generate_repro(
        &self,
        Parameters(params): Parameters<GenerateReproParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Some(f) = params.format.as_deref()
            && !f.eq_ignore_ascii_case("sipp")
        {
            return Err(rmcp::ErrorData::invalid_params(
                format!("unknown format '{f}'; 'sipp' is the only one"),
                None,
            ));
        }

        let pin = normalize_aspects(params.pin.as_deref(), &[], "pin")?;
        let vary = normalize_aspects(params.vary.as_deref(), DEFAULT_VARY, "vary")?;
        for a in &vary {
            if !VARIABLE_ASPECTS.contains(&a.as_str()) {
                return Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "'{a}' cannot be varied: SIPp has no generator for it. \
                         Variable aspects are {}. Pin it instead if it is part \
                         of your hypothesis.",
                        VARIABLE_ASPECTS.join(", ")
                    ),
                    None,
                ));
            }
        }
        for a in &pin {
            if vary.contains(a) {
                return Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "'{a}' is in both pin and vary. Held fixed and \
                         regenerated are opposite instructions, and a scenario \
                         that silently picked one would encode a theory nobody \
                         stated."
                    ),
                    None,
                ));
            }
        }

        // Resolved before the store lock for the same reason the suppression
        // file is: it touches the filesystem.
        let out_path = match params.filename.as_deref() {
            Some(name) => Some(self.resolve_in_root_for_write(name)?),
            None => None,
        };

        let built = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;
            let built = build_sipp_scenario(dialog, &pin, &vary)?;
            drop(ds);
            built
        };

        let mut payload = serde_json::json!({
            "schema_version": 1,
            "call_id": params.call_id,
            "format": "sipp",
            "hypothesis": {
                "pinned": pin,
                "varied": vary,
                "generated": built.generated,
                "omitted": built.omitted,
            },
            "asserted": {
                "provisional": built.provisional,
                "final": built.final_status,
            },
            "scenario": built.xml,
            "run": "sipp -sf <scenario.xml> -m 1 <proxy-host>:<port>",
            "caveats": built.caveats,
        });

        if let Some(path) = out_path {
            std::fs::write(&path, built.xml_bytes).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("writing {}: {e}", path.display()), None)
            })?;
            tracing::info!(
                "MCP generate_repro wrote a SIPp scenario for {} to {}",
                params.call_id,
                path.display()
            );
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "path".to_string(),
                    serde_json::Value::String(path.display().to_string()),
                );
            }
        }

        // The scenario embeds Request-URI, header values and SDP the packet's
        // sender wrote. It is returned as a document rather than fenced field
        // by field, so the note is what marks the whole of it.
        Ok(CallToolResult::success(vec![
            ContentBlock::json(payload)?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }

    /// Build a Wireshark display filter selecting one call.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown `call_id`, or a Call-ID
    /// carrying a control character — a display-filter string literal has no
    /// escape for one, so the filter could not be written to mean what the
    /// Call-ID says.
    #[tool(
        name = "generate_wireshark_filter",
        description = "Returns a Wireshark display filter selecting one call's \
                       signaling, plus its RTP streams by SSRC unless \
                       include_media is false, and the tshark command line that \
                       applies it. The Call-ID is escaped for a display-filter \
                       string literal.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn generate_wireshark_filter(
        &self,
        Parameters(params): Parameters<GenerateWiresharkFilterParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let include_media = params.include_media.unwrap_or(true);

        let (ssrcs, source) = {
            // Capture lock first, then the stores — see `CaptureState`. The
            // source name is part of the answer (it becomes `tshark -r`), so it
            // must describe the same capture the SSRCs came from.
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;
            let ss = self.stream_store.read();
            let ssrcs: Vec<u32> = if include_media {
                let mut v: Vec<u32> = ss
                    .streams_for(&params.call_id)
                    .map(|s| s.key.ssrc)
                    .collect();
                v.sort_unstable();
                v.dedup();
                v
            } else {
                Vec::new()
            };
            let source = state
                .context
                .as_ref()
                .filter(|c| !c.live)
                .map(|c| c.name.clone());
            drop(ss);
            drop(ds);
            drop(state);
            (ssrcs, source)
        };

        let mut filter = format!(
            "sip.Call-ID == \"{}\"",
            escape_display_filter_string(&params.call_id)?
        );
        for ssrc in &ssrcs {
            filter.push_str(&format!(" || rtp.ssrc == 0x{ssrc:08x}"));
        }

        let mut notes = Vec::new();
        if include_media && ssrcs.is_empty() {
            notes.push(
                "no RTP stream is attributed to this call, so the filter \
                 selects signaling only"
                    .to_string(),
            );
        }
        if !ssrcs.is_empty() {
            notes.push(
                "rtp.ssrc matches only once Wireshark is decoding those packets \
                 as RTP. Enable 'Try to decode RTP outside of conversations', \
                 or use Decode As on the media ports, if the SSRC terms select \
                 nothing."
                    .to_string(),
            );
        }

        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::json!({
                "schema_version": 1,
                "call_id": params.call_id,
                "display_filter": filter,
                "tshark": format!(
                    "tshark -r {} -Y {}",
                    shell_quote(source.as_deref().unwrap_or("<capture.pcap>")),
                    shell_quote(&filter)
                ),
                "streams_included": ssrcs.len(),
                "notes": notes,
            }),
        )?]))
    }

    /// Build a fail2ban filter and jail from one recorded security finding.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when no detector was armed on this server,
    /// when `finding_id` is not one this server holds (the message lists the
    /// ids it does hold), or when the recorded rule name is not a bare
    /// identifier and could not be written into a regular expression as itself.
    #[tool(
        name = "generate_fail2ban_rule",
        description = "Returns a fail2ban filter and jail stanza derived from \
                       ONE recorded security finding, with that finding \
                       attached as the evidence. The failregex matches the \
                       '[ALERT] <rule> src=<ip> <detail>' line sipnab writes, so \
                       it needs sipnab started with --alert syslog or its stderr \
                       captured to a file. maxretry, findtime and bantime are \
                       fail2ban's own conventional starting values and are not \
                       measurements sipnab made. The detail line carries text \
                       the packet's sender wrote.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn generate_fail2ban_rule(
        &self,
        Parameters(params): Parameters<GenerateFail2banRuleParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let Some(engine) = self.alert_engine.as_ref() else {
            return Err(rmcp::ErrorData::invalid_params(
                "this server holds no findings: no detection rule was armed, so \
                 nothing could have been recorded. Arm one with --kill-scanner, \
                 --fraud-detect, --digest-leak or --reg-flood and re-run the \
                 capture."
                    .to_string(),
                None,
            ));
        };

        let (found, available) = {
            let guard = engine.read();
            // The whole ring buffer, for the reason `security_findings` walks
            // all of it: a truncated scan cannot report what it truncated, and
            // here the truncated part is the list of ids the caller is offered.
            let all = guard.iter_findings(&[], None, usize::MAX);
            let found = all
                .iter()
                .find(|f| finding_id(f) == params.finding_id)
                .map(|f| (f.rule_name.clone(), f.src_ip, f.detail.clone(), f.timestamp));
            let available: Vec<String> = all
                .iter()
                .take(self.row_cap)
                .map(|f| finding_id(f))
                .collect();
            drop(guard);
            (found, available)
        };

        let Some((rule_name, src_ip, detail, timestamp)) = found else {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "no finding with id '{}'. An id is \
                     <rule_name>@<src_ip>@<timestamp>, built from the three \
                     fields security_findings returns. This server holds: {}",
                    params.finding_id,
                    if available.is_empty() {
                        "none".to_string()
                    } else {
                        available.join(", ")
                    }
                ),
                None,
            ));
        };

        // The rule name is written into a regular expression as itself, so it
        // has to BE itself. Every name the detectors file under is a bare
        // identifier; anything else would be a regex the author did not write.
        if !rule_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || rule_name.is_empty()
        {
            return Err(rmcp::ErrorData::internal_error(
                format!(
                    "recorded rule name '{rule_name}' is not a bare identifier \
                     and cannot be written into a failregex verbatim"
                ),
                None,
            ));
        }

        let jail = format!("sipnab-{rule_name}");
        let mut caveats = vec![
            format!(
                "the failregex matches sipnab's own alert line. Start sipnab \
                 with '--alert syslog' (or capture its stderr to the logpath) \
                 or the {jail} jail will never see a match."
            ),
            "maxretry, findtime and bantime below are fail2ban's conventional \
             starting values, not figures sipnab measured on this traffic. \
             Choose them from your own false-positive tolerance."
                .to_string(),
            "one finding is evidence that this detector fired, not that every \
             future match is an attacker. The jail bans any source the detector \
             reports, including this one."
                .to_string(),
        ];
        if src_ip.is_loopback() {
            caveats.push(format!(
                "{src_ip} is a loopback address: a jail acting on it would ban \
                 this host from itself"
            ));
        }

        let filter_conf = format!(
            "# Generated by sipnab from finding {}\n\
             [Definition]\n\
             failregex = ^.*\\[ALERT\\] {rule_name} src=<HOST> .*$\n\
             ignoreregex =\n",
            params.finding_id
        );
        let jail_conf = format!(
            "[{jail}]\n\
             enabled  = true\n\
             filter   = {jail}\n\
             logpath  = /var/log/syslog\n\
             port     = 5060,5061\n\
             protocol = udp\n\
             maxretry = 3\n\
             findtime = 600\n\
             bantime  = 3600\n"
        );

        Ok(CallToolResult::success(vec![
            ContentBlock::json(serde_json::json!({
                "schema_version": 1,
                "finding_id": params.finding_id,
                "evidence": {
                    "rule_name": rule_name,
                    "src_ip": src_ip.to_string(),
                    // Fenced: the detail line quotes headers the sender wrote.
                    "detail": crate::mcp::shape::fence(
                        &crate::mcp::shape::truncate_string(&detail, self.body_cap)
                    ),
                    "timestamp": timestamp.to_rfc3339(),
                },
                "filter_name": jail,
                "filter_path": format!("/etc/fail2ban/filter.d/{jail}.conf"),
                "filter_conf": filter_conf,
                "jail_path": format!("/etc/fail2ban/jail.d/{jail}.conf"),
                "jail_conf": jail_conf,
                "log_line_format": "[ALERT] <rule_name> src=<ip> <detail>",
                "caveats": caveats,
            }))?,
            ContentBlock::text(crate::mcp::shape::untrusted_note()),
        ]))
    }
}

/// The identifier one recorded finding is addressed by.
///
/// Derived from the three fields `security_findings` already returns, rather
/// than assigned by the ring buffer. An assigned id would have to survive
/// eviction, restart and a second server reading the same capture, and none of
/// those are true of a position in a bounded queue — an agent holding id 7
/// across a restart would act on a different finding.
fn finding_id(f: &crate::security::alerting::Finding) -> String {
    format!("{}@{}@{}", f.rule_name, f.src_ip, f.timestamp.to_rfc3339())
}

/// Lower-case, de-duplicate and validate a caller's aspect list.
///
/// # Errors
///
/// `invalid_params` (-32602) naming the offending aspect and the vocabulary.
fn normalize_aspects(
    given: Option<&[String]>,
    default: &[&str],
    field: &str,
) -> Result<Vec<String>, rmcp::ErrorData> {
    let mut out: Vec<String> = match given {
        // An explicitly empty list means "none", not "the default". `pin: []`
        // is how a caller says the scenario tests no theory, and substituting a
        // default there would put a hypothesis in the artifact that nobody
        // stated.
        Some(list) => list.iter().map(|s| s.trim().to_lowercase()).collect(),
        None => default.iter().map(|s| (*s).to_string()).collect(),
    };
    for a in &out {
        if !REPRO_ASPECTS.contains(&a.as_str()) {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "unknown {field} aspect '{a}'; one of: {}",
                    REPRO_ASPECTS.join(", ")
                ),
                None,
            ));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// A scenario and everything the answer says about it.
struct BuiltScenario {
    /// The SIPp XML.
    xml: String,
    /// The same text as bytes, for the optional file write.
    xml_bytes: Vec<u8>,
    /// Aspects the template supplies instead of the capture.
    generated: Vec<&'static str>,
    /// Aspects present in the capture and absent from the scenario.
    omitted: Vec<&'static str>,
    /// Provisional response codes the scenario expects, in ascending order.
    provisional: Vec<u16>,
    /// The final response code the scenario asserts, when the capture held one.
    final_status: Option<u16>,
    /// Everything true of the artifact that its text does not say.
    caveats: Vec<String>,
}

/// Build the SIPp scenario for one dialog.
///
/// # Errors
///
/// `invalid_params` (-32602) when the dialog holds no request to replay, or
/// when a pinned SDP body is not valid UTF-8 and could not be embedded as text.
fn build_sipp_scenario(
    dialog: &crate::sip::dialog::SipDialog,
    pin: &[String],
    vary: &[String],
) -> Result<BuiltScenario, rmcp::ErrorData> {
    let pinned = |a: &str| pin.iter().any(|p| p == a);
    let varied = |a: &str| vary.iter().any(|v| v == a);

    let request = dialog
        .messages
        .iter()
        .find(|m| m.is_request)
        .ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                format!(
                    "call '{}' holds no request in this capture, so there is \
                 nothing to replay. A capture that begins mid-dialog has only \
                 responses.",
                    dialog.call_id
                ),
                None,
            )
        })?;
    let method = request
        .method
        .as_ref()
        .map_or("INVITE", crate::sip::method::SipMethod::as_str)
        .to_string();

    let mut caveats = Vec::new();
    let mut generated: Vec<&'static str> = vec!["via", "contact", "max_forwards", "content_length"];
    let mut omitted: Vec<&'static str> = Vec::new();

    // ── The request line ────────────────────────────────────────────
    let request_uri = if pinned("request_uri") {
        request
            .request_uri
            .as_deref()
            .map(sanitize_line)
            .unwrap_or_else(|| "sip:[remote_ip]:[remote_port]".to_string())
    } else {
        generated.push("request_uri");
        match request.to_user() {
            Some(u) => format!("sip:{}@[remote_ip]:[remote_port]", sanitize_line(&u)),
            None => "sip:[remote_ip]:[remote_port]".to_string(),
        }
    };

    // ── Identity ────────────────────────────────────────────────────
    let call_id = if pinned("call_id") {
        sanitize_line(&dialog.call_id)
    } else {
        if !varied("call_id") {
            generated.push("call_id");
        }
        "[call_id]".to_string()
    };
    let from_tag = if pinned("tags") {
        request
            .from_tag()
            .map_or_else(|| "[pid]SIPpTag00[call_number]".to_string(), sanitize_line)
    } else {
        if !varied("tags") {
            generated.push("tags");
        }
        "[pid]SIPpTag00[call_number]".to_string()
    };
    let branch = if pinned("branch") {
        request
            .top_via_branch()
            .map_or_else(|| "[branch]".to_string(), sanitize_line)
    } else {
        if !varied("branch") {
            generated.push("branch");
        }
        "[branch]".to_string()
    };
    let cseq = if pinned("cseq") {
        request.cseq().map_or(1, |(n, _)| n)
    } else {
        generated.push("cseq");
        1
    };

    let from_user = request
        .from_user()
        .map_or_else(|| "sipp".to_string(), |u| sanitize_line(&u));
    let to_user = request
        .to_user()
        .map_or_else(|| "service".to_string(), |u| sanitize_line(&u));

    // ── Optional pinned detail ──────────────────────────────────────
    let mut extra_headers = String::new();
    if pinned("user_agent") {
        if let Some(ua) = request.user_agent() {
            extra_headers.push_str(&format!("User-Agent: {}\n", sanitize_line(ua)));
        } else {
            caveats.push(
                "user_agent was pinned and the captured request carries no \
                 User-Agent header, so none is sent"
                    .to_string(),
            );
        }
    } else {
        omitted.push("user_agent");
    }
    if pinned("headers") {
        for h in &request.headers {
            let lower = h.name.to_lowercase();
            if SCENARIO_OWNED_HEADERS.contains(&lower.as_str()) {
                continue;
            }
            extra_headers.push_str(&format!(
                "{}: {}\n",
                sanitize_line(&h.name),
                sanitize_line(&h.value)
            ));
        }
    } else {
        omitted.push("headers");
    }

    // ── The body ────────────────────────────────────────────────────
    // The captured Content-Type travels with a pinned body, because the aspect
    // pins BYTES and the label has to describe them. A multipart body announced
    // as application/sdp is a message the far end rejects for a reason that has
    // nothing to do with the theory under test.
    let mut content_type = "application/sdp".to_string();
    let sdp = if pinned("sdp") {
        if request.body.is_empty() {
            caveats.push(
                "sdp was pinned and the captured request carries no body, so a \
                 generic PCMU offer is sent instead"
                    .to_string(),
            );
            generated.push("sdp");
            generic_sdp_offer()
        } else {
            let text = std::str::from_utf8(&request.body).map_err(|e| {
                rmcp::ErrorData::invalid_params(
                    format!(
                        "the captured body of call '{}' is not valid UTF-8 ({e}) \
                         and cannot be embedded in a scenario as text. Drop \
                         'sdp' from pin to send a generic offer instead.",
                        dialog.call_id
                    ),
                    None,
                )
            })?;
            caveats.push(
                "the pinned body names the media endpoint the ORIGINAL caller \
                 advertised, so any RTP the far end sends goes there and not to \
                 the machine running SIPp"
                    .to_string(),
            );
            if let Some(ct) = request.content_type() {
                content_type = sanitize_line(ct);
            }
            text.replace("\r\n", "\n")
        }
    } else {
        generated.push("sdp");
        caveats.push(
            "the offer is a generic PCMU one, not the capture's. Pin 'sdp' if \
             the media description is part of your hypothesis — a codec or \
             attribute the far end rejected will not be present otherwise."
                .to_string(),
        );
        generic_sdp_offer()
    };

    // ── What the capture said came back ─────────────────────────────
    let mut provisional: Vec<u16> = dialog
        .messages
        .iter()
        .filter_map(|m| m.status_code)
        .filter(|c| (100..200).contains(c))
        .collect();
    // 100 whether or not the capture held one: a proxy on the replay path may
    // emit it, and an unexpected message SIPp was not told about is an error.
    provisional.push(100);
    provisional.sort_unstable();
    provisional.dedup();
    let final_status = dialog.final_status_code();

    if pin.is_empty() {
        caveats.push(
            "nothing is pinned, so this scenario encodes no hypothesis: it \
             replays the call generically, and reproducing the outcome would \
             not show what caused it"
                .to_string(),
        );
    }
    caveats.push(
        "SIPp sends from the host you run it on. Source address, routing and \
         any IP access list differ from the capture, and a reproduction depends \
         on those matching."
            .to_string(),
    );
    if final_status.is_none() {
        caveats.push(
            "the capture holds no final response for this call, so the scenario \
             asserts nothing about the outcome: it sends the request and waits."
                .to_string(),
        );
    }

    generated.sort_unstable();
    generated.dedup();
    omitted.sort_unstable();

    // ── Assemble ────────────────────────────────────────────────────
    let mut body = String::new();
    body.push_str(&format!("{method} {request_uri} SIP/2.0\n"));
    body.push_str("Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=");
    body.push_str(&branch);
    body.push('\n');
    body.push_str(&format!(
        "From: <sip:{from_user}@[local_ip]:[local_port]>;tag={from_tag}\n"
    ));
    body.push_str(&format!("To: <sip:{to_user}@[remote_ip]:[remote_port]>\n"));
    body.push_str(&format!("Call-ID: {call_id}\n"));
    body.push_str(&format!("CSeq: {cseq} {method}\n"));
    body.push_str("Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n");
    body.push_str("Max-Forwards: 70\n");
    body.push_str(&extra_headers);
    body.push_str(&format!("Content-Type: {content_type}\n"));
    body.push_str("Content-Length: [len]\n\n");
    body.push_str(&sdp);
    if !body.ends_with('\n') {
        body.push('\n');
    }

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n");
    xml.push_str("<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n");
    xml.push_str(&format!(
        "<!-- Generated by sipnab from Call-ID {} -->\n\
         <!-- pinned: {} | varied: {} -->\n",
        xml_comment_safe(&dialog.call_id),
        if pin.is_empty() {
            "(nothing)".to_string()
        } else {
            pin.join(" ")
        },
        if vary.is_empty() {
            "(nothing)".to_string()
        } else {
            vary.join(" ")
        }
    ));
    xml.push_str(&format!(
        "<scenario name=\"sipnab repro {}\">\n",
        xml_attr_safe(&dialog.call_id)
    ));
    xml.push_str(&send_block(&body, Some("500")));
    for code in &provisional {
        xml.push_str(&format!(
            "  <recv response=\"{code}\" optional=\"true\"/>\n"
        ));
    }

    if let Some(code) = final_status {
        xml.push_str(&format!("  <recv response=\"{code}\"/>\n"));
        // ACK either way, and the difference is which Via it carries. A 2xx
        // ACK is a new transaction and takes a new branch; a non-2xx ACK is
        // part of the INVITE transaction and must echo the Via it was answered
        // on (RFC 3261 section 17.1.1.3), which `[last_Via:]` does exactly.
        if method == "INVITE" {
            let via = if (200..300).contains(&code) {
                "Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]".to_string()
            } else {
                "[last_Via:]".to_string()
            };
            let ack = format!(
                "ACK {request_uri} SIP/2.0\n\
                 {via}\n\
                 [last_From:]\n\
                 [last_To:]\n\
                 [last_Call-ID:]\n\
                 CSeq: {cseq} ACK\n\
                 Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n\
                 Max-Forwards: 70\n\
                 Content-Length: 0\n\n"
            );
            xml.push_str(&send_block(&ack, None));

            if (200..300).contains(&code) {
                xml.push_str("  <pause milliseconds=\"2000\"/>\n");
                let bye = format!(
                    "BYE {request_uri} SIP/2.0\n\
                     Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n\
                     [last_From:]\n\
                     [last_To:]\n\
                     [last_Call-ID:]\n\
                     CSeq: {} BYE\n\
                     Max-Forwards: 70\n\
                     Content-Length: 0\n\n",
                    cseq + 1
                );
                xml.push_str(&send_block(&bye, Some("500")));
                xml.push_str("  <recv response=\"200\"/>\n");
            }
        }
    } else {
        xml.push_str("  <pause milliseconds=\"4000\"/>\n");
    }
    xml.push_str("</scenario>\n");

    let xml_bytes = xml.clone().into_bytes();
    Ok(BuiltScenario {
        xml,
        xml_bytes,
        generated,
        omitted,
        provisional,
        final_status,
        caveats,
    })
}

/// One `<send>` element wrapping a SIP message in CDATA.
fn send_block(message: &str, retrans: Option<&str>) -> String {
    let open = match retrans {
        Some(ms) => format!("  <send retrans=\"{ms}\">\n"),
        None => "  <send>\n".to_string(),
    };
    format!(
        "{open}    <![CDATA[\n\n{}\n    ]]>\n  </send>\n",
        cdata_safe(message)
    )
}

/// The generic offer a scenario sends when the SDP is not part of the theory.
///
/// The stock SIPp `uac` offer, using SIPp's own media placeholders so the far
/// end answers to the host running the test rather than to the captured caller.
fn generic_sdp_offer() -> String {
    "v=0\n\
     o=sipnab 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n\
     s=-\n\
     c=IN IP[media_ip_type] [media_ip]\n\
     t=0 0\n\
     m=audio [media_port] RTP/AVP 0\n\
     a=rtpmap:0 PCMU/8000\n"
        .to_string()
}

/// Make text safe to place inside an XML CDATA section.
///
/// `]]>` is the only sequence CDATA cannot carry, and it arrives from the wire:
/// a header value or SDP attribute containing it would close the section early
/// and the rest of the message would be parsed as markup. Splitting it across
/// two sections is the standard remedy and preserves the bytes exactly.
fn cdata_safe(s: &str) -> String {
    s.replace("]]>", "]]]]><![CDATA[>")
}

/// Strip anything from a captured value that would forge structure in the
/// message being built.
///
/// Header values reach here as the sender wrote them. A CR or LF inside one
/// would end the header and start another, which is header injection into an
/// artifact an operator is about to run against their own proxy; the other
/// control characters have no meaning in a SIP header and no way to be typed
/// back. Removed rather than escaped because a SIP header has no escape for
/// them.
fn sanitize_line(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect()
}

/// Make text safe inside an XML comment.
///
/// `--` terminates a comment early in every conforming parser, so it cannot
/// survive as itself.
fn xml_comment_safe(s: &str) -> String {
    sanitize_line(s).replace("--", "__")
}

/// Make text safe inside a double-quoted XML attribute.
fn xml_attr_safe(s: &str) -> String {
    sanitize_line(s)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Escape a captured value for a Wireshark display-filter string literal.
///
/// # Errors
///
/// `invalid_params` (-32602) when the value carries a control character. The
/// display-filter grammar escapes `\` and `"` and nothing else, so a filter
/// built around a control character would either fail to compile or select
/// something other than what it names — and a filter that quietly selects the
/// wrong packets is worse than no filter.
fn escape_display_filter_string(s: &str) -> Result<String, rmcp::ErrorData> {
    if let Some(c) = s.chars().find(|c| c.is_control()) {
        return Err(rmcp::ErrorData::invalid_params(
            format!(
                "this Call-ID carries the control character U+{:04X}, which a \
                 Wireshark display-filter string literal cannot represent. A \
                 filter written around it would not mean what the Call-ID says.",
                c as u32
            ),
            None,
        ));
    }
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Quote a value for a POSIX shell command line.
///
/// Single quotes, with any embedded single quote closed and re-opened around an
/// escaped one — the only form that survives arbitrary text, and the answer
/// carries a Call-ID the sender chose.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    use parking_lot::RwLock;
    use std::sync::Arc;

    /// A fixed timestamp, so no fixture here depends on the clock.
    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 6, 15, 12, 0, 0)
            .single()
            .unwrap_or_default()
    }

    /// Parse `raw` as SIP between two localhost endpoints.
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

    /// An SDP offer distinctive enough that its presence in a scenario is not
    /// something the generic template could have produced.
    const PINNED_SDP: &str = "v=0\r\no=orig 1 1 IN IP4 198.51.100.7\r\ns=-\r\n\
                              c=IN IP4 198.51.100.7\r\nt=0 0\r\n\
                              m=audio 41234 RTP/AVP 96\r\n\
                              a=rtpmap:96 SPEEX/16000\r\n";

    /// An INVITE carrying SDP, a User-Agent and one extension header.
    fn invite_with_sdp(call_id: &str, extra: &[&str]) -> crate::sip::SipMessage {
        let mut headers: Vec<String> = vec![
            "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKcaptured".to_string(),
            "From: Alice <sip:alice@example.com>;tag=capturedtag".to_string(),
            "To: <sip:bob@example.com>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 314 INVITE".to_string(),
            "User-Agent: CapturedUA/9.9".to_string(),
            "X-Trunk-Hint: north-east".to_string(),
            "Content-Type: application/sdp".to_string(),
            format!("Content-Length: {}", PINNED_SDP.len()),
        ];
        headers.extend(extra.iter().map(|h| (*h).to_string()));
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        parse_at(&crate::test_utils::build_sip_message(
            "INVITE sip:bob@example.com;user=phone SIP/2.0",
            &refs,
            PINNED_SDP.as_bytes(),
        ))
    }

    /// The matching final response.
    fn response(call_id: &str, code: u16, reason: &str) -> crate::sip::SipMessage {
        parse_at(&crate::test_utils::build_sip_message(
            &format!("SIP/2.0 {code} {reason}"),
            &[
                "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKcaptured",
                "From: Alice <sip:alice@example.com>;tag=capturedtag",
                "To: <sip:bob@example.com>;tag=remotetag",
                &format!("Call-ID: {call_id}"),
                "CSeq: 314 INVITE",
                "Contact: <sip:bob@203.0.113.9>",
                "Content-Length: 0",
            ],
            b"",
        ))
    }

    /// A server over empty stores.
    fn empty_server() -> SipnabMcp {
        SipnabMcp::new(
            Arc::new(RwLock::new(DialogStore::new(64, false))),
            Arc::new(RwLock::new(StreamStore::new(64))),
        )
    }

    /// A server holding one call that ended in `code`.
    fn server_with_call(call_id: &str, code: u16, extra_headers: &[&str]) -> SipnabMcp {
        let mut ds = DialogStore::new(64, false);
        ds.process_message(invite_with_sdp(call_id, extra_headers));
        ds.process_message(response(call_id, code, "Not Acceptable Here"));
        SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(StreamStore::new(64))),
        )
    }

    /// The payload block of a result, skipping the untrusted-content note.
    fn payload(result: &CallToolResult) -> serde_json::Value {
        let note = crate::mcp::shape::untrusted_note();
        let text = result
            .content
            .iter()
            .filter_map(rmcp::model::ContentBlock::as_text)
            .map(|t| t.text.clone())
            .find(|t| *t != note)
            .expect("a payload block that is not the note");
        serde_json::from_str(&text).expect("payload is JSON")
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

    // ── evaluate_expectations ───────────────────────────────────────

    /// A call naming no rules is refused rather than reporting a verdict on
    /// nothing.
    #[tokio::test]
    async fn evaluate_expectations_refuses_a_call_with_no_rules() {
        let err = empty_server()
            .evaluate_expectations(Parameters(EvaluateExpectationsParams::default()))
            .await
            .expect_err("no rules must be refused");
        assert_eq!(code_of(err), -32602);
    }

    /// Two suites in one call are refused, because the answer could not say
    /// which one it judged.
    #[tokio::test]
    async fn evaluate_expectations_refuses_two_rule_sources_at_once() {
        let err = empty_server()
            .evaluate_expectations(Parameters(EvaluateExpectationsParams {
                rules: Some(vec![ExpectRule {
                    name: None,
                    metric: "count".to_string(),
                    op: crate::expect::Op::Ge,
                    value: 0.0,
                    scope: None,
                    min_sample: None,
                    grounded_only: None,
                }]),
                rules_toml: Some("[[rules]]\nmetric='count'\nop='>='\nvalue=0\n".to_string()),
                suppression_file: None,
            }))
            .await
            .expect_err("both sources must be refused");
        assert_eq!(code_of(err), -32602);
    }

    /// The checked-in file's own text is a rule source, and it produces the
    /// same verdict an inline rule would.
    #[tokio::test]
    async fn evaluate_expectations_reads_a_rule_file_verbatim_and_fails_a_violation() {
        let server = server_with_call("gate@x", 488, &[]);
        let v = payload(
            &server
                .evaluate_expectations(Parameters(EvaluateExpectationsParams {
                    rules: None,
                    rules_toml: Some(
                        "[[rules]]\n\
                         name = 'no codec rejections'\n\
                         metric = 'count'\n\
                         op = '=='\n\
                         value = 0\n\
                         scope = \"filter:response_code == 488\"\n"
                            .to_string(),
                    ),
                    suppression_file: None,
                }))
                .await
                .expect("the suite evaluates"),
        );
        assert_eq!(v["verdict"], "fail", "{v}");
        assert_eq!(v["exit_code"], 1);
        assert_eq!(v["results"][0]["observed"], 1.0);
        assert_eq!(v["results"][0]["name"], "no codec rejections");
        assert!(
            v["capture_identity"].is_object(),
            "the verdict must name the capture it judged: {v}"
        );
    }

    /// A misspelled metric is refused by name rather than silently evaluating
    /// to a verdict.
    #[tokio::test]
    async fn evaluate_expectations_refuses_an_unknown_metric() {
        let err = empty_server()
            .evaluate_expectations(Parameters(EvaluateExpectationsParams {
                rules: Some(vec![ExpectRule {
                    name: None,
                    metric: "acd".to_string(),
                    op: crate::expect::Op::Ge,
                    value: 1.0,
                    scope: None,
                    min_sample: None,
                    grounded_only: None,
                }]),
                rules_toml: None,
                suppression_file: None,
            }))
            .await
            .expect_err("an unknown metric must be refused");
        let msg = message_of(err);
        assert!(msg.contains("acd") && msg.contains("lint_errors"), "{msg}");
    }

    // ── generate_repro ──────────────────────────────────────────────

    /// Run `generate_repro` and return its payload.
    async fn repro(server: &SipnabMcp, params: GenerateReproParams) -> serde_json::Value {
        payload(
            &server
                .generate_repro(Parameters(params))
                .await
                .expect("scenario builds"),
        )
    }

    /// Nothing pinned means nothing of the capture's own detail is carried, and
    /// the answer says the artifact encodes no theory.
    #[tokio::test]
    async fn an_unpinned_scenario_carries_a_generic_offer_and_says_it_tests_nothing() {
        let server = server_with_call("repro@x", 488, &[]);
        let v = repro(
            &server,
            GenerateReproParams {
                call_id: "repro@x".to_string(),
                ..Default::default()
            },
        )
        .await;
        let xml = v["scenario"].as_str().unwrap_or_default();
        assert!(
            !xml.contains("SPEEX/16000"),
            "an unpinned SDP must not reach the scenario: {xml}"
        );
        assert!(xml.contains("a=rtpmap:0 PCMU/8000"), "{xml}");
        assert!(
            !xml.contains("CapturedUA/9.9"),
            "an unpinned User-Agent must not reach the scenario: {xml}"
        );
        assert!(
            v["caveats"].as_array().is_some_and(|c| c.iter().any(|s| s
                .as_str()
                .is_some_and(|s| s.contains("encodes no hypothesis")))),
            "{v}"
        );
        assert_eq!(
            v["hypothesis"]["varied"],
            serde_json::json!(["branch", "call_id", "tags"])
        );
    }

    /// Pinning is what pulls the capture's own detail in, and the hypothesis
    /// block reports exactly what was held fixed.
    #[tokio::test]
    async fn pinning_carries_the_captured_detail_into_the_scenario() {
        let server = server_with_call("repro@x", 488, &[]);
        let v = repro(
            &server,
            GenerateReproParams {
                call_id: "repro@x".to_string(),
                pin: Some(vec![
                    "sdp".to_string(),
                    "user_agent".to_string(),
                    "headers".to_string(),
                    "request_uri".to_string(),
                    "cseq".to_string(),
                ]),
                ..Default::default()
            },
        )
        .await;
        let xml = v["scenario"].as_str().unwrap_or_default();
        assert!(xml.contains("a=rtpmap:96 SPEEX/16000"), "{xml}");
        assert!(xml.contains("User-Agent: CapturedUA/9.9"), "{xml}");
        assert!(xml.contains("X-Trunk-Hint: north-east"), "{xml}");
        assert!(xml.contains("sip:bob@example.com;user=phone"), "{xml}");
        assert!(xml.contains("CSeq: 314 INVITE"), "{xml}");
        // The identity fields still vary: a pinned hypothesis must not turn the
        // replay into a retransmission of the captured call.
        assert!(xml.contains("Call-ID: [call_id]"), "{xml}");
        assert!(xml.contains("branch=[branch]"), "{xml}");
    }

    /// The recv sequence asserts the outcome the capture actually held.
    #[tokio::test]
    async fn the_scenario_asserts_the_response_the_capture_held() {
        let server = server_with_call("repro@x", 488, &[]);
        let v = repro(
            &server,
            GenerateReproParams {
                call_id: "repro@x".to_string(),
                ..Default::default()
            },
        )
        .await;
        let xml = v["scenario"].as_str().unwrap_or_default();
        assert!(xml.contains("<recv response=\"488\"/>"), "{xml}");
        assert_eq!(v["asserted"]["final"], 488);
        // A non-2xx ACK belongs to the INVITE transaction and must echo the Via
        // it was answered on.
        assert!(xml.contains("[last_Via:]"), "{xml}");
        assert!(
            !xml.contains("BYE "),
            "a call that never answered has nothing to tear down: {xml}"
        );

        let answered = server_with_call("ok@x", 200, &[]);
        let v = repro(
            &answered,
            GenerateReproParams {
                call_id: "ok@x".to_string(),
                ..Default::default()
            },
        )
        .await;
        let xml = v["scenario"].as_str().unwrap_or_default();
        assert!(xml.contains("<recv response=\"200\"/>"), "{xml}");
        assert!(xml.contains("BYE "), "an answered call is torn down: {xml}");
    }

    /// A pinned body travels with the Content-Type that described it.
    ///
    /// Pinning names BYTES, and a body announced under the wrong label is a
    /// message the far end rejects for a reason that is not the hypothesis.
    #[tokio::test]
    async fn a_pinned_body_keeps_the_content_type_that_described_it() {
        let mut ds = DialogStore::new(64, false);
        ds.process_message(parse_at(&crate::test_utils::build_sip_message(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKcaptured",
                "From: Alice <sip:alice@example.com>;tag=capturedtag",
                "To: <sip:bob@example.com>",
                "Call-ID: mixed@x",
                "CSeq: 1 INVITE",
                "Content-Type: multipart/mixed;boundary=uniqueBoundary",
                "Content-Length: 4",
            ],
            b"body",
        )));
        ds.process_message(response("mixed@x", 415, "Unsupported Media Type"));
        let server = SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(StreamStore::new(64))),
        );
        let v = repro(
            &server,
            GenerateReproParams {
                call_id: "mixed@x".to_string(),
                pin: Some(vec!["sdp".to_string()]),
                ..Default::default()
            },
        )
        .await;
        let xml = v["scenario"].as_str().unwrap_or_default();
        assert!(
            xml.contains("Content-Type: multipart/mixed;boundary=uniqueBoundary"),
            "{xml}"
        );
        assert!(
            !xml.contains("Content-Type: application/sdp"),
            "the captured label replaces the default, not joins it: {xml}"
        );
    }

    /// A header value carrying CR/LF cannot forge a header in the artifact.
    #[tokio::test]
    async fn a_crlf_in_a_captured_header_cannot_forge_a_header_in_the_scenario() {
        // The parser keeps the value on one line, so the injection is staged
        // through a value the sender could still write: a lone CR.
        let server = server_with_call("inject@x", 488, &["X-Evil: a\rRoute: <sip:attacker>"]);
        let v = repro(
            &server,
            GenerateReproParams {
                call_id: "inject@x".to_string(),
                pin: Some(vec!["headers".to_string()]),
                ..Default::default()
            },
        )
        .await;
        let xml = v["scenario"].as_str().unwrap_or_default();
        assert!(
            !xml.contains('\r'),
            "no carriage return may survive into the scenario: {xml:?}"
        );
        assert!(
            xml.contains("X-Evil: aRoute: <sip:attacker>"),
            "the value stays on its own header line: {xml}"
        );
    }

    /// A `]]>` in captured text cannot close the CDATA section early.
    #[tokio::test]
    async fn a_cdata_terminator_in_captured_text_is_split_rather_than_emitted() {
        let server = server_with_call("cdata@x", 488, &["X-Payload: ]]><evil/>"]);
        let v = repro(
            &server,
            GenerateReproParams {
                call_id: "cdata@x".to_string(),
                pin: Some(vec!["headers".to_string()]),
                ..Default::default()
            },
        )
        .await;
        let xml = v["scenario"].as_str().unwrap_or_default();
        assert!(
            xml.contains("]]]]><![CDATA[>"),
            "the terminator must be split across two sections: {xml}"
        );
        assert!(
            !xml.contains("]]><evil/>"),
            "the section must not close early: {xml}"
        );
    }

    /// An aspect named in both pin and vary is refused: they are opposite
    /// instructions and picking one silently would invent a hypothesis.
    #[tokio::test]
    async fn an_aspect_in_both_pin_and_vary_is_refused() {
        let err = server_with_call("repro@x", 488, &[])
            .generate_repro(Parameters(GenerateReproParams {
                call_id: "repro@x".to_string(),
                pin: Some(vec!["call_id".to_string()]),
                vary: Some(vec!["call_id".to_string()]),
                ..Default::default()
            }))
            .await
            .expect_err("a contradiction must be refused");
        assert_eq!(code_of(err), -32602);
    }

    /// An aspect SIPp cannot regenerate is refused from `vary`, naming the ones
    /// it can.
    #[tokio::test]
    async fn an_aspect_with_no_generator_is_refused_from_vary() {
        let err = server_with_call("repro@x", 488, &[])
            .generate_repro(Parameters(GenerateReproParams {
                call_id: "repro@x".to_string(),
                vary: Some(vec!["sdp".to_string()]),
                ..Default::default()
            }))
            .await
            .expect_err("an unvariable aspect must be refused");
        let msg = message_of(err);
        assert!(
            msg.contains("cannot be varied") && msg.contains("call_id"),
            "{msg}"
        );
    }

    /// An aspect outside the vocabulary is refused by name.
    #[tokio::test]
    async fn an_unknown_aspect_is_refused_by_name() {
        let err = server_with_call("repro@x", 488, &[])
            .generate_repro(Parameters(GenerateReproParams {
                call_id: "repro@x".to_string(),
                pin: Some(vec!["contact".to_string()]),
                ..Default::default()
            }))
            .await
            .expect_err("an unknown aspect must be refused");
        let msg = message_of(err);
        assert!(
            msg.contains("contact") && msg.contains("request_uri"),
            "{msg}"
        );
    }

    /// Only `sipp` is generated, and anything else is refused rather than
    /// silently producing a SIPp file under another name.
    #[tokio::test]
    async fn an_unknown_repro_format_is_refused() {
        let err = server_with_call("repro@x", 488, &[])
            .generate_repro(Parameters(GenerateReproParams {
                call_id: "repro@x".to_string(),
                format: Some("pjsua".to_string()),
                ..Default::default()
            }))
            .await
            .expect_err("an unknown format must be refused");
        assert_eq!(code_of(err), -32602);
    }

    // ── generate_wireshark_filter ───────────────────────────────────

    /// The Call-ID is escaped for a display-filter string literal, and the
    /// tshark line survives a Call-ID containing a shell metacharacter.
    #[tokio::test]
    async fn a_wireshark_filter_escapes_the_call_id_it_quotes() {
        let call_id = "a\"b\\c'd@host";
        let server = server_with_call(call_id, 488, &[]);
        let v = payload(
            &server
                .generate_wireshark_filter(Parameters(GenerateWiresharkFilterParams {
                    call_id: call_id.to_string(),
                    include_media: None,
                }))
                .await
                .expect("filter builds"),
        );
        assert_eq!(
            v["display_filter"], "sip.Call-ID == \"a\\\"b\\\\c'd@host\"",
            "{v}"
        );
        assert_eq!(
            v["tshark"],
            "tshark -r '<capture.pcap>' -Y 'sip.Call-ID == \"a\\\"b\\\\c'\\''d@host\"'",
            "the single quote must be closed and reopened, not left to end the \
             shell word: {v}"
        );
    }

    /// A control character in a Call-ID is refused: a display filter has no
    /// escape for one, and a filter that quietly selects the wrong packets is
    /// worse than none.
    #[tokio::test]
    async fn a_control_character_in_a_call_id_is_refused() {
        let call_id = "bad\u{7}id@host";
        let err = server_with_call(call_id, 488, &[])
            .generate_wireshark_filter(Parameters(GenerateWiresharkFilterParams {
                call_id: call_id.to_string(),
                include_media: None,
            }))
            .await
            .expect_err("a control character must be refused");
        assert!(message_of(err).contains("U+0007"));
    }

    /// An unknown Call-ID errors rather than returning a filter that selects
    /// nothing.
    #[tokio::test]
    async fn a_wireshark_filter_for_an_unknown_call_errors() {
        let err = empty_server()
            .generate_wireshark_filter(Parameters(GenerateWiresharkFilterParams {
                call_id: "nobody@nowhere".to_string(),
                include_media: None,
            }))
            .await
            .expect_err("an unknown call must be refused");
        assert_eq!(code_of(err), -32602);
    }

    // ── generate_fail2ban_rule ──────────────────────────────────────

    /// With no detector armed there are no findings, and the refusal says that
    /// rather than emitting a rule about nothing.
    #[tokio::test]
    async fn a_fail2ban_rule_without_a_detector_is_refused() {
        let err = empty_server()
            .generate_fail2ban_rule(Parameters(GenerateFail2banRuleParams {
                finding_id: "scanner@192.0.2.1@2026-01-01T00:00:00+00:00".to_string(),
            }))
            .await
            .expect_err("no engine must be refused");
        let msg = message_of(err);
        assert!(msg.contains("--kill-scanner"), "{msg}");
    }

    /// A server holding one scanner finding, and that finding's id.
    fn server_with_finding() -> (SipnabMcp, String) {
        let mut engine = crate::security::alerting::AlertEngine::new(vec![], None);
        engine.fire(
            "scanner",
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 66)),
            "method=OPTIONS detection=enumeration",
            ts(),
        );
        let id = {
            let findings = engine.iter_findings(&[], None, usize::MAX);
            let f = findings.first().expect("the fire was recorded");
            finding_id(f)
        };
        let server = empty_server()
            .with_alert_engine(Arc::new(RwLock::new(engine)))
            .with_armed_detections(["scanner"]);
        (server, id)
    }

    /// The generated failregex matches the line sipnab actually writes, for the
    /// rule the finding names.
    #[tokio::test]
    async fn a_fail2ban_rule_matches_the_alert_line_sipnab_writes() {
        let (server, id) = server_with_finding();
        let v = payload(
            &server
                .generate_fail2ban_rule(Parameters(GenerateFail2banRuleParams {
                    finding_id: id.clone(),
                }))
                .await
                .expect("the rule builds"),
        );
        let conf = v["filter_conf"].as_str().unwrap_or_default();
        assert!(
            conf.contains("failregex = ^.*\\[ALERT\\] scanner src=<HOST> .*$"),
            "{conf}"
        );
        assert_eq!(v["filter_name"], "sipnab-scanner");
        assert_eq!(v["evidence"]["src_ip"], "198.51.100.66");
        assert_eq!(v["finding_id"], id);
        // The evidence quotes a detail line built from headers a sender wrote.
        assert!(
            v["evidence"]["detail"]
                .as_str()
                .is_some_and(|d| d.contains(crate::mcp::shape::UNTRUSTED_OPEN)),
            "the detail must be fenced: {v}"
        );
        assert!(
            v["caveats"].as_array().is_some_and(|c| c.iter().any(|s| s
                .as_str()
                .is_some_and(|s| s.contains("not figures sipnab measured")))),
            "the conventional defaults must not read as measurements: {v}"
        );
    }

    /// An id this server does not hold is refused, and the refusal offers the
    /// ids it does hold.
    #[tokio::test]
    async fn an_unknown_finding_id_lists_the_ones_that_exist() {
        let (server, id) = server_with_finding();
        let err = server
            .generate_fail2ban_rule(Parameters(GenerateFail2banRuleParams {
                finding_id: "scanner@10.0.0.1@2020-01-01T00:00:00+00:00".to_string(),
            }))
            .await
            .expect_err("an unknown id must be refused");
        let msg = message_of(err);
        assert!(
            msg.contains(&id),
            "the refusal must name what is available: {msg}"
        );
    }

    // ── helpers ─────────────────────────────────────────────────────

    /// The shell quoter closes and reopens around an embedded quote.
    #[test]
    fn shell_quoting_survives_an_embedded_single_quote() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    /// Control characters are removed and tabs kept.
    #[test]
    fn sanitize_line_removes_control_characters_but_keeps_tabs() {
        assert_eq!(sanitize_line("a\rb\nc\u{0}d\te"), "abcd\te");
    }
}
