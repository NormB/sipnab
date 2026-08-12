// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tool descriptions must not instruct the model what to believe (D22).
//!
//! An MCP tool description is read by an LLM before it reads any data, so it
//! is the one piece of text in the exchange the model treats as authoritative.
//! A description that says "verify this" or "act on the result" tells the model
//! to trust content it has not yet seen — and that content is captured SIP,
//! which is attacker-controlled. A `From:` header is a string a stranger chose.
//!
//! So descriptions state what a tool RETURNS and stop. The rule is written in
//! `src/mcp/server.rs` under "Tool descriptions and prompt-injection defense
//! (D22)", where it cited `scripts/check-tool-descriptions.sh` — a script that
//! was never written. A cited gate that does not exist is worse than an
//! unenforced convention, because it reads as enforced: the rule survived only
//! as long as everyone who added a tool happened to follow it.
//!
//! Implemented as a Rust test rather than the shell script the plan named. This
//! repository has already been bitten once by a shell gate duplicating a Rust
//! one and the two drifting apart (the version-marker check, removed 2026-07-27
//! after it rejected a correct release commit). One implementation, run by
//! `cargo test` like every other gate here.

/// Imperative verbs that tell the model how to treat returned content.
///
/// Deliberately matched as whole words. "verify" must fail, but a description
/// mentioning a "verification code" field should not — the rule is about
/// instructions to the model, not about vocabulary.
const FORBIDDEN: &[&str] = &["trust", "act on", "verify", "ensure"];

/// Extract `description = "..."` string literals from the `#[tool]` attributes.
///
/// The attribute form is `#[tool(name = "...", description = "...")]` with the
/// description usually spanning several lines as a Rust string continuation.
fn tool_descriptions(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(idx) = rest.find("name = \"") {
        let after = &rest[idx + 8..];
        let Some(end) = after.find('"') else { break };
        let name = after[..end].to_string();

        // The description follows the name inside the same attribute; stop at
        // the closing `)]` so a later tool's text cannot bleed into this one.
        let tail = &after[end..];
        let bound = tail.find(")]").unwrap_or(tail.len());
        let attr = &tail[..bound];
        if let Some(d) = attr.find("description = \"") {
            let body = &attr[d + 15..];
            // Walk to the closing quote, honouring escapes and the `\` line
            // continuations these multi-line descriptions use.
            let mut text = String::new();
            let mut chars = body.chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(n) = chars.next()
                            && n != '\n'
                        {
                            text.push(n);
                        }
                    }
                    '"' => break,
                    _ => text.push(c),
                }
            }
            out.push((name, text));
        }
        rest = &rest[idx + 8..];
    }
    out
}

/// No `#[tool]` description tells the model to trust, verify, ensure or act on
/// what it gets back.
#[test]
fn tool_descriptions_do_not_instruct_the_model_to_trust_content() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src =
        std::fs::read_to_string(repo.join("src/mcp/server.rs")).expect("read src/mcp/server.rs");
    let tools = tool_descriptions(&src);

    // Pinned. The extractor is a hand-rolled scan over attribute text, and the
    // way it fails is by matching nothing and passing vacuously — which is
    // exactly the failure this whole file exists to prevent.
    assert!(
        tools.len() >= 20,
        "found only {} tool descriptions in src/mcp/server.rs — the attribute \
         shape changed and this gate is no longer reading the registry",
        tools.len()
    );

    let mut violations = Vec::new();
    for (name, desc) in &tools {
        let lower = desc.to_lowercase();
        for word in FORBIDDEN {
            // Whole-word match so "verification" does not trip "verify".
            let hit = lower.match_indices(word).any(|(i, _)| {
                let before = lower[..i].chars().next_back();
                let after = lower[i + word.len()..].chars().next();
                let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
                boundary(before) && boundary(after)
            });
            if hit {
                violations.push(format!("{name}: contains {word:?} — {desc}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "MCP tool descriptions must state what the tool RETURNS, never tell the \
         model how to treat the content (D22). An LLM reads these before it \
         reads any data, and the data is captured SIP — attacker-controlled \
         text. Violations:\n  {}",
        violations.join("\n  ")
    );
}

/// A tool whose output could be mistaken for a recording must say it is not.
///
/// The export writes one re-synthesised Ethernet/IP/UDP frame per held SIP
/// message, because the dialog store keeps parsed messages and not the original
/// bytes. So the file holds no RTP, carries reconstructed link and IP headers,
/// and on a measured corpus export was missing 97.5% of the packets that had
/// been on the wire.
///
/// None of that was a secret: the function's own doc comment says it plainly and
/// calls the result "honest about the rest". The problem was WHERE it was said.
/// An MCP client reads the tool description and nothing else, so a caveat living
/// in a code comment reaches the one reader who does not need it and misses the
/// one who does. The output is a pcap, and a pcap is evidence — it gets attached
/// to carrier tickets and regulator filings by people who never saw either text.
///
/// This gate keeps the disclosure at the layer the consumer actually reads.
#[test]
fn an_export_that_synthesises_frames_says_so_where_the_model_reads() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src =
        std::fs::read_to_string(repo.join("src/mcp/server.rs")).expect("read src/mcp/server.rs");

    let export = tool_descriptions(&src)
        .into_iter()
        .find(|(name, _)| {
            name.contains("export") && name.contains("capture") || name == "export_signalling"
        })
        .expect("an export tool is registered");

    let lower = export.1.to_lowercase();
    let discloses = ["synthes", "reconstruct", "rebuilt", "re-synthes"]
        .iter()
        .any(|w| lower.contains(w));
    assert!(
        discloses,
        "the '{}' tool description must say the frames are re-synthesised rather \
         than captured. Without it the model is told it is preserving packets and \
         hands on a reconstruction that reads as a recording. Description was: {}",
        export.0, export.1
    );

    let names_the_gap =
        lower.contains("rtp") || lower.contains("signalling") || lower.contains("signaling");
    assert!(
        names_the_gap,
        "the '{}' description must name what the file does NOT contain — it holds \
         no RTP, only signalling. 'Re-synthesised' alone still reads as complete. \
         Description was: {}",
        export.0, export.1
    );
}

/// The module doc must not cite a gate that does not exist.
///
/// `src/mcp/server.rs` pointed at `scripts/check-tool-descriptions.sh` for
/// years; the script was never written, so the rule read as enforced while
/// nothing checked it. If the citation comes back, the file it names has to be
/// there.
#[test]
fn the_cited_description_gate_actually_exists() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src =
        std::fs::read_to_string(repo.join("src/mcp/server.rs")).expect("read src/mcp/server.rs");

    for line in src.lines().take(40) {
        if let Some(idx) = line.find("scripts/") {
            let path: String = line[idx..]
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '`' && *c != '.' || *c == '.')
                .collect();
            let path = path.trim_end_matches('.');
            assert!(
                repo.join(path).exists(),
                "src/mcp/server.rs cites {path}, which does not exist. Either \
                 write it or cite the gate that really runs — a named check \
                 that is absent reads as enforced and is not."
            );
        }
    }
}

/// Every tool the server registers has BOTH a call example and a response
/// example in `docs/mcp.md`.
///
/// A response example alone is half a specification. `capture_health` showed
/// what comes back and never showed a call — and it takes a REQUIRED
/// `sample_seconds`, so a reader could not discover the one thing they had to
/// supply. `list_captures` and `render_ladder` had the same shape: the reader
/// learns what the answer looks like and has to guess the question.
///
/// The tool list comes from the SOURCE, not from the documentation, so adding
/// a `#[tool]` without documenting it fails here rather than going unnoticed —
/// which is the direction the drift actually runs.
#[test]
fn every_mcp_tool_documents_a_call_and_a_response() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp/server.rs"),
    )
    .expect("read src/mcp/server.rs");
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/mcp.md"),
    )
    .expect("read docs/mcp.md");

    const FENCE: &str = "```";
    let tools = tool_descriptions(&src);
    assert!(
        tools.len() >= 25,
        "only {} tools were extracted from the source, so this gate is checking \
         almost nothing — the `#[tool]` attribute shape changed",
        tools.len()
    );

    let mut problems = Vec::new();
    for (name, _) in &tools {
        let heading = format!("### `{name}`");
        let Some(start) = doc.find(&heading) else {
            problems.push(format!("{name}: no `{heading}` section in docs/mcp.md"));
            continue;
        };
        let after = &doc[start + heading.len()..];
        let section = match after.find("\n### ") {
            Some(end) => &after[..end],
            None => after,
        };

        // A CALL is shown as `tool_name { ... }`, or the section states the
        // tool takes none — which is a complete specification for a nullary
        // tool, not an omission.
        let shows_call = section.contains(&format!("{name} {{"))
            || section.contains(&format!("\"name\": \"{name}\""))
            || section.to_lowercase().contains("no parameters");
        // A RESPONSE is any fenced json/jsonc/text block in the section.
        let shows_response = ["json", "jsonc", "text"]
            .iter()
            .any(|k| section.contains(&format!("{FENCE}{k}")));

        if !shows_call {
            problems.push(format!(
                "{name}: documents a response but never shows how to CALL it. \
                 A reader cannot discover a required parameter from an answer"
            ));
        }
        if !shows_response {
            problems.push(format!("{name}: shows a call but no response shape"));
        }
    }

    problems.sort();
    assert!(
        problems.is_empty(),
        "every MCP tool needs a complete example — a call AND a response:\n  {}",
        problems.join("\n  ")
    );
}
