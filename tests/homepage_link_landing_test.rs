// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every link on the homepage lands where the words around it say it does.
//!
//! # Why this gate exists
//!
//! On 2026-10-13 an audit of the live homepage found every link answering 200
//! and every anchor resolving, and still found links that did not answer the
//! question the card asked. "Audio, notes and names" sent the reader to the
//! RTP Streams section, which says nothing about playing audio, notes or
//! names. "Digest and STIR/SHAKEN" sent the reader to the top of a cookbook of
//! more than 60 recipes. A status code and an anchor prove that a page exists.
//! They do not prove that the page holds what the link promised.
//!
//! So each link has a row naming the terms its landing must hold:
//!
//! - **A link with a `#fragment`** lands on one section: the heading with that
//!   slug and everything up to the next heading of the same or a higher level.
//!   Every term must appear in that section.
//! - **A link to a whole page** lands at the top of it. The first term must
//!   appear before the page's first `##` heading, so the reader sees at once
//!   that the page is the right one. The other terms may appear anywhere on
//!   the page.
//!
//! A link with no row fails, and so does a row with no link, so a new card
//! cannot skip the check and a removed one cannot leave a stale row.
//!
//! Absolute links are pinned in [`EXTERNAL`] in the form that answers 200
//! without a redirect, measured with `curl` when each row was added.

use std::collections::BTreeSet;
use std::path::Path;

/// Any error, boxed, so `?` works on I/O, parse and lookup failures alike.
type TestError = Box<dyn std::error::Error>;

/// One homepage link: the target as the template writes it, with
/// `get_url(path='@/X')` shortened to `@/X`, and the link's visible text.
type Link = (String, String);

/// `(target, link text, terms the landing must hold)`.
///
/// Terms are matched without regard to case, against the markdown source of
/// the landing with link targets removed.
type Landing = (&'static str, &'static str, &'static [&'static str]);

/// Every internal link on the homepage, and what its landing must hold.
const LANDINGS: &[Landing] = &[
    // Hero.
    ("@/docs/install.md", "Get started", &["install"]),
    ("@/analyze/_index.md", "Try a sample capture", &["pcap"]),
    // What it does: three summary tiles.
    (
        "@/docs/tui.md",
        "Inspect",
        &["terminal", "ladder", "retransmi", "mark"],
    ),
    (
        "@/docs/cookbook.md",
        "Diagnose",
        &["recipe", "jitter", "one-way", "NAT", "post-dial delay"],
    ),
    (
        "@/docs/output-formats.md",
        "Export",
        &[
            "format",
            "PCAP-NG",
            "NDJSON",
            "Mermaid",
            "Wireshark",
            "fail2ban",
            "WAV",
        ],
    ),
    // Figures.
    (
        "@/docs/benchmarks.md",
        "3.52M pkts/s",
        &["benchmark", "3.52", "four"],
    ),
    (
        "@/docs/mcp-tools.md",
        "74 MCP tools",
        &["tool", "lint", "evidence", "correlat"],
    ),
    // Trust.
    (
        "@/cla.md",
        "📝 Contributor License Agreement",
        &["Contributor License Agreement"],
    ),
    (
        "@/docs/install.md#verify-a-download-is-genuine",
        "🔏 Signed build provenance",
        &["provenance", "SBOM"],
    ),
    // System map: what it reads.
    (
        "@/docs/cli.md#capture",
        "A live network interface",
        &["-d", "interface"],
    ),
    (
        "@/docs/cli.md#capture",
        "pcap and pcapng files, folders, archives",
        &["-I", "pcap"],
    ),
    (
        "@/docs/homer-sipnab.md",
        "HEP copies from OpenSIPS, Kamailio, rtpengine",
        &["HEP", "-L"],
    ),
    (
        "@/docs/tls-capture.md",
        "Encrypted SIP, with TLS keys or kernel uprobes",
        &["TLS", "--keylog", "--uprobe-tls"],
    ),
    (
        "@/docs/encapsulations.md",
        "VLAN, MPLS, GTP-U, VXLAN, WebSocket",
        &["VLAN", "MPLS", "GTP-U", "VXLAN", "WebSocket"],
    ),
    (
        "@/docs/rtpengine-sipnab.md",
        "Media relay: rtpengine",
        &["rtpengine", "--rtpengine-control"],
    ),
    (
        "@/docs/rtpproxy-sipnab.md",
        "Media relay: rtpproxy",
        &["rtpproxy", "--rtpproxy-control"],
    ),
    // System map: where you read it.
    ("@/docs/tui.md", "An interactive terminal UI", &["terminal"]),
    (
        "@/docs/output-formats.md",
        "Text, JSON and reports for scripts",
        &["format", "--json", "-N"],
    ),
    ("@/docs/api.md", "A REST API", &["REST", "--api"]),
    (
        "@/docs/mcp.md",
        "An MCP server for AI agents",
        &["MCP", "--mcp"],
    ),
    (
        "@/docs/prometheus-sipnab.md",
        "Prometheus metrics",
        &["Prometheus", "--metrics"],
    ),
    ("@/docs/homer-sipnab.md", "HEP to Homer", &["HEP", "-H"]),
    (
        "@/docs/vcon-sipnab.md",
        "vCon records",
        &["vCon", "--export-vcon"],
    ),
    (
        "@/docs/fail2ban-sipnab.md",
        "Alerts and fail2ban",
        &["fail2ban", "syslog", "--fail2ban"],
    ),
    (
        "@/docs/tfps-sipnab.md",
        "TFPS bans, journaled and revertible",
        &["TFPS", "--allow-action", "journal", "revert"],
    ),
    (
        "@/docs/internals/_index.md",
        "How it works inside",
        &["changing sipnab"],
    ),
    // Capabilities: capture.
    ("@/docs/cli.md#capture", "Live capture", &["interface"]),
    (
        "@/docs/keybindings.md#capture-filter-editor",
        "capture filter editable from the terminal UI",
        &["capture filter"],
    ),
    (
        "@/docs/cli.md#archives",
        "Files and archives",
        &["pcap", "glob", "tar", "ZIP", "7z", "password"],
    ),
    (
        "@/docs/integrations.md#forward-to-homer-over-hep",
        "HEP v1/v2/v3",
        &["HEP", "Homer", "Kamailio", "OpenSIPS", "Asterisk"],
    ),
    (
        "@/docs/encapsulations.md",
        "Tunnels and transports",
        &[
            "VLAN",
            "MPLS",
            "GRE",
            "VXLAN",
            "WebSocket",
            "fragment",
            "TCP",
        ],
    ),
    (
        "@/docs/tls-capture.md",
        "TLS/SRTP decryption",
        &["TLS", "SSLKEYLOGFILE", "RSA", "SRTP", "SDES", "DTLS"],
    ),
    (
        "@/docs/uprobe-walkthrough.md",
        "TLS capture with uprobes",
        &["uprobe", "OpenSSL", "wolfSSL", "BTF", "tracefs"],
    ),
    (
        "@/docs/uprobe-walkthrough.md",
        "Read the security implications first",
        &["uprobe", "security"],
    ),
    // Capabilities: diagnose.
    (
        "@/docs/mos-and-codecs.md",
        "RTP quality analysis",
        &["MOS", "jitter", "loss", "G.107", "RTCP XR"],
    ),
    (
        "@/docs/cookbook.md#diagnose-a-one-way-audio-complaint",
        "VoIP diagnosis",
        &["one-way", "NAT", "SDP"],
    ),
    (
        "@/docs/cli.md#measure-post-dial-delay-across-calls",
        "calls slow to ring",
        &["post-dial delay", "--slow-setup"],
    ),
    (
        "@/docs/cli.md#dialog",
        "Calls across legs",
        &["leg", "B2BUA"],
    ),
    (
        "@/docs/output-formats.md#capture-analysis-json-analyze",
        "Ranked analysis",
        &["--analyze", "rank"],
    ),
    (
        "@/docs/sip-lint-rules.md",
        "Conformance linter",
        &["lint", "RFC", "--lint-fail-on", "exit"],
    ),
    (
        "@/docs/cookbook.md#ask-a-relay-whether-it-is-dropping-packets",
        "Relay statistics",
        &["rtpengine", "counter"],
    ),
    (
        "@/docs/filter-dsl.md",
        "Filter DSL",
        &["filter", "alias", "named filter"],
    ),
    // Capabilities: call records.
    (
        "@/docs/vcon.md",
        "Export as vCon",
        &["vCon", "rule", "filter"],
    ),
    (
        "@/docs/vcon.md#calls-through-a-pbx-or-a-b2bua",
        "Calls through a PBX",
        &["PBX", "leg", "per call"],
    ),
    (
        "@/docs/vcon.md#enrich-a-call-before-it-is-written",
        "Enrichment",
        &["transcri", "summariz", "analysis"],
    ),
    (
        "@/docs/vcon.md#hear-a-call-while-it-is-in-progress",
        "Live calls",
        &["WebSocket", "audio"],
    ),
    (
        "@/docs/vcon.md#follow-a-call-while-it-is-in-progress",
        "containers rewritten as the call changes",
        &["rewrit"],
    ),
    (
        "@/docs/vcon.md#encrypt-what-a-rule-writes",
        "Signed and encrypted",
        &["JWS", "JWE", "encrypt_to", "certificate"],
    ),
    (
        "@/docs/vcon-store.md",
        "Deliver to a store",
        &["vcon.store", "--vcon-forward", "--vcon-fetch"],
    ),
    (
        "@/docs/vcon.md#analyze-a-stored-vcon",
        "Read stored vCons",
        &["-I", "TUI"],
    ),
    // Capabilities: protect.
    (
        "@/docs/cli.md#security",
        "Attack detection",
        &["scanner", "fraud", "wangiri", "--reg-flood"],
    ),
    (
        "@/docs/cookbook.md#detect-weak-digest-authentication-on-a-registrar",
        "Digest and STIR/SHAKEN",
        &["digest"],
    ),
    (
        "@/docs/cookbook.md#check-what-a-stir-shaken-identity-header-actually-claims",
        "decodes STIR/SHAKEN PASSporT claims",
        &["STIR", "PASSporT"],
    ),
    (
        "@/docs/cookbook.md#detect-sip-scanners-and-auto-block-via-fail2ban",
        "fail2ban and firewall rules",
        &["fail2ban", "--recommend-block"],
    ),
    (
        "@/docs/tfps-sipnab.md",
        "TFPS bans",
        &["TFPS", "journal", "revert"],
    ),
    (
        "@/docs/cli.md#output",
        "Pseudonymized vCons",
        &["pseudonym", "reverse"],
    ),
    (
        "@/docs/cli.md#privilege",
        "Hardened process",
        &["root", "--user"],
    ),
    (
        "@/docs/cli.md#security",
        "Landlock and seccomp",
        &["--sandbox", "Landlock", "--seccomp"],
    ),
    // Capabilities: terminal UI.
    (
        "@/docs/tui.md",
        "Terminal UI and headless mode",
        &["terminal", "call flow", "diff"],
    ),
    (
        "@/docs/keybindings.md#quality-dashboard",
        "Quality views",
        &["MOS", "loss"],
    ),
    (
        "@/docs/keybindings.md#carrier-metrics",
        "Carrier views",
        &["ASR", "NER", "ACD"],
    ),
    (
        "@/docs/keybindings.md#top-talkers",
        "top talkers",
        &["talker"],
    ),
    (
        "@/docs/keybindings.md#call-volume-histogram",
        "call-volume histogram",
        &["histogram"],
    ),
    (
        "@/docs/keybindings.md#stream-detail",
        "Audio, notes and names",
        &["play"],
    ),
    (
        "@/docs/keybindings.md#operator-notes",
        "saves notes as PCAP-NG packet comments",
        &["note", "PCAP-NG", "comment"],
    ),
    (
        "@/docs/keybindings.md#name-resolution",
        "names hosts from hosts files and DNS",
        &["hosts", "DNS"],
    ),
    // Capabilities: integrate.
    ("@/docs/api.md", "REST API", &["REST", "token", "TLS"]),
    ("@/docs/mcp.md", "MCP server", &["MCP", "stdio", "HTTP"]),
    (
        "@/docs/mcp.md#tools-that-write-or-act",
        "the thirteen that write files or act on the host",
        &["--mcp-file-root", "--allow-action", "--mcp-allow-shutdown"],
    ),
    (
        "@/docs/metrics.md",
        "Prometheus metrics",
        &["Prometheus", "MOS", "jitter"],
    ),
    (
        "@/docs/keybindings.md#save-popup",
        "Export formats",
        &[
            "PCAP", "PCAP-NG", "NDJSON", "CSV", "Markdown", "WAV", "SIPp", "RTP JSON",
        ],
    ),
    (
        "@/docs/output-formats.md#yang-export-yang-analyze",
        "YANG (RFC 7951)",
        &["YANG", "7951"],
    ),
    ("@/docs/vcon.md", "vCon", &["vCon"]),
    (
        "@/docs/plugins.md",
        "WASM plugins",
        &["WebAssembly", "--plugin", "musl"],
    ),
    (
        "@/analyze/_index.md",
        "Browser analysis",
        &["browser", "nothing leaves"],
    ),
    (
        "@/docs/build.md#rust-and-unsafe",
        "Built in Rust",
        &["unsafe", "SAFETY", "soundness", "size ceiling"],
    ),
    ("@/features.md", "Every capability", &["what sipnab does"]),
    // MCP demo.
    (
        "@/analyze/_index.md",
        "Or open your own capture in the browser",
        &["browser"],
    ),
    // Where it fits.
    ("@/docs/opensips.md", "Use OpenSIPS", &["OpenSIPS"]),
    (
        "@/docs/opensips-sipnab.md",
        "Run sipnab beside it",
        &["OpenSIPS"],
    ),
    ("@/docs/kamailio.md", "Use Kamailio", &["Kamailio"]),
    (
        "@/docs/kamailio-sipnab.md",
        "Run sipnab beside it",
        &["Kamailio"],
    ),
    ("@/docs/asterisk.md", "Use Asterisk", &["Asterisk"]),
    (
        "@/docs/asterisk-sipnab.md",
        "Run sipnab beside it",
        &["Asterisk"],
    ),
    ("@/docs/freeswitch.md", "Use FreeSWITCH", &["FreeSWITCH"]),
    (
        "@/docs/freeswitch-sipnab.md",
        "Run sipnab beside it",
        &["FreeSWITCH"],
    ),
    (
        "@/docs/vcon-server.md",
        "Use a vCon server",
        &["vCon server"],
    ),
    ("@/docs/vcon-sipnab.md", "Run sipnab beside it", &["vCon"]),
    (
        "@/docs/vcon-store.md",
        "Send to vcon.store",
        &["vcon.store"],
    ),
    ("@/docs/tfps.md", "Use TFPS", &["TFPS"]),
    ("@/docs/tfps-sipnab.md", "Run sipnab beside it", &["TFPS"]),
    ("@/docs/fail2ban.md", "Use fail2ban", &["fail2ban"]),
    (
        "@/docs/fail2ban-sipnab.md",
        "Run sipnab beside it",
        &["fail2ban"],
    ),
    ("@/docs/rtpengine-relay.md", "Use rtpengine", &["rtpengine"]),
    (
        "@/docs/rtpengine-sipnab.md",
        "Run sipnab beside it",
        &["rtpengine"],
    ),
    ("@/docs/rtpproxy-relay.md", "Use rtpproxy", &["rtpproxy"]),
    (
        "@/docs/rtpproxy-sipnab.md",
        "Run sipnab beside it",
        &["rtpproxy"],
    ),
    ("@/docs/homer.md", "Use Homer", &["Homer"]),
    ("@/docs/homer-sipnab.md", "Run sipnab beside it", &["Homer"]),
    (
        "@/docs/prometheus.md",
        "Use Prometheus and Grafana",
        &["Prometheus"],
    ),
    (
        "@/docs/prometheus-sipnab.md",
        "Run sipnab beside it",
        &["Prometheus"],
    ),
    // Standards and notes.
    (
        "@/standards.md",
        "See the standards behind every number",
        &["standard", "IETF"],
    ),
    ("@/notes/_index.md", "All notes", &["note"]),
];

/// Every absolute link on the homepage, in the form that answers 200 with no
/// redirect (measured with `curl -sS -o /dev/null -w '%{http_code}'` on
/// 2026-10-13). `rfc-editor.org/rfc/rfcNNNN` without `.html` answers 302 to a
/// metadata page, not to the RFC.
///
/// One entry redirects on purpose. bestpractices.dev publishes the badge link
/// as `/projects/13931`, and `tests/openssf_badge_test.rs` pins that form. It
/// answers 302 to `/en/projects/13931`, then to that project's own badge page,
/// so the reader lands on the page the link names.
const EXTERNAL: &[&str] = &[
    "https://github.com/sipcapture/homer",
    "https://www.bestpractices.dev/projects/13931",
    "https://www.rfc-editor.org/rfc/rfc3261.html",
    "https://www.rfc-editor.org/rfc/rfc3550.html",
];

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The homepage template with HTML and Tera comments removed: a comment is
/// not something a visitor reads.
fn homepage() -> Result<String, TestError> {
    let raw = std::fs::read_to_string(repo().join("website/templates/index.html"))?;
    let html = regex::Regex::new(r"(?s)<!--.*?-->")?.replace_all(&raw, "");
    Ok(regex::Regex::new(r"(?s)\{#.*?#\}")?
        .replace_all(&html, "")
        .into_owned())
}

/// Every link on `html` whose target is a site page (`@/…`) or an absolute
/// URL, with its visible text, tags removed and whitespace collapsed.
fn links(html: &str) -> Result<Vec<Link>, TestError> {
    let anchor = regex::Regex::new(r#"(?s)<a\s[^>]*href="([^"]+)"[^>]*>(.*?)</a>"#)?;
    let get_url = regex::Regex::new(r"\{\{ get_url\(path='(@/[^']+)'\) \}\}")?;
    let tags = regex::Regex::new(r"<[^>]+>")?;
    let mut out = Vec::new();
    for c in anchor.captures_iter(html) {
        let target = get_url.replace(&c[1], "$1").into_owned();
        if !(target.starts_with("@/") || target.starts_with("http")) {
            continue;
        }
        let text = tags.replace_all(&c[2], "");
        let text = text
            .replace("&rarr;", "")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        out.push((target, text));
    }
    Ok(out)
}

/// Zola's slug for a markdown heading: lowercase, runs of anything that is not
/// a letter or digit become one `-`, trimmed. A heading with an explicit
/// `{#id}` takes that id.
fn slug(heading: &str) -> String {
    if let Some(open) = heading.rfind("{#")
        && let Some(id) = heading[open + 2..].strip_suffix('}')
    {
        return id.to_string();
    }
    let mut out = String::new();
    for ch in heading.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// The heading level and text of a markdown line, outside code fences.
fn heading(line: &str) -> Option<(usize, &str)> {
    let level = line.bytes().take_while(|b| *b == b'#').count();
    (1..=6)
        .contains(&level)
        .then(|| line[level..].strip_prefix(' '))
        .flatten()
        .map(|text| (level, text.trim()))
}

/// The lines of `md` with front matter dropped. A line inside a fenced code
/// block is kept, indented by one space so that a shell `# comment` in an
/// example is never read as a heading.
fn prose_lines(md: &str) -> Vec<String> {
    let body = md
        .strip_prefix("+++")
        .and_then(|rest| rest.find("\n+++").map(|end| &rest[end + 4..]))
        .unwrap_or(md);
    let mut fenced = false;
    let mut out = Vec::new();
    for line in body.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            out.push(format!(" {line}"));
        } else if fenced {
            out.push(format!(" {line}"));
        } else {
            out.push(line.to_string());
        }
    }
    out
}

/// What a reader landing on `anchor` of `md` reads: the heading with that
/// slug and everything up to the next heading of the same or a higher level.
/// `None` when no heading has that slug.
fn section(md: &str, anchor: &str) -> Option<String> {
    let lines = prose_lines(md);
    let start = lines
        .iter()
        .position(|l| heading(l).is_some_and(|(_, text)| slug(text) == anchor))?;
    let (level, _) = heading(&lines[start])?;
    let end = lines[start + 1..]
        .iter()
        .position(|l| heading(l).is_some_and(|(lv, _)| lv <= level))
        .map_or(lines.len(), |i| start + 1 + i);
    Some(lines[start..end].join("\n"))
}

/// The front matter title and description, and everything before the first
/// `##` heading: what a reader sees on arriving at the top of a page. A page
/// that a template renders from its front matter alone shows its title and
/// description first.
fn opening(md: &str) -> String {
    let front = |key: &str| {
        md.lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or("")
            .to_string()
    };
    let title = format!("{}\n{}", front("title = "), front("description = "));
    let lines = prose_lines(md);
    let end = lines
        .iter()
        .position(|l| heading(l).is_some_and(|(lv, _)| lv == 2))
        .unwrap_or(lines.len());
    format!("{title}\n{}", lines[..end].join("\n"))
}

/// `text` with markdown link targets removed, so a term that appears only in
/// a URL does not count as the page stating it.
fn readable(text: &str) -> Result<String, TestError> {
    Ok(regex::Regex::new(r"\]\([^)]*\)")?
        .replace_all(text, "]")
        .to_lowercase())
}

/// The terms of `row` its landing does not hold, or why the landing could not
/// be read. `page_of` maps `X.md` under `website/content` to its text.
fn missing_terms(
    row: &Landing,
    page_of: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<String>, TestError> {
    let (target, _, terms) = row;
    let rel = target.trim_start_matches("@/");
    let (path, anchor) = rel
        .split_once('#')
        .map_or((rel, None), |(p, a)| (p, Some(a)));
    let Some(md) = page_of(path) else {
        return Ok(vec![format!("page {path} does not exist")]);
    };
    let (first, rest) = match anchor {
        Some(a) => {
            let Some(s) = section(&md, a) else {
                return Ok(vec![format!("no heading in {path} has the slug {a}")]);
            };
            let s = readable(&s)?;
            (s.clone(), s)
        }
        None => (readable(&opening(&md))?, readable(&md)?),
    };
    let mut out = Vec::new();
    for (i, term) in terms.iter().enumerate() {
        let haystack = if i == 0 { &first } else { &rest };
        if !haystack.contains(&term.to_lowercase()) {
            out.push(if anchor.is_none() && i == 0 {
                format!("{term:?} (not in the page's opening section)")
            } else {
                format!("{term:?}")
            });
        }
    }
    Ok(out)
}

/// A page under `website/content`, by its path relative to that directory.
fn content_page(rel: &str) -> Option<String> {
    std::fs::read_to_string(repo().join("website/content").join(rel)).ok()
}

/// Every homepage link has a row, and every row is a link on the homepage.
#[test]
fn every_homepage_link_has_a_landing_row() -> Result<(), TestError> {
    let found = links(&homepage()?)?;
    let internal: BTreeSet<(String, String)> = found
        .iter()
        .filter(|(t, _)| t.starts_with("@/"))
        .cloned()
        .collect();
    assert!(
        internal.len() >= 60,
        "only {} internal link(s) read from the homepage; the link scan is broken",
        internal.len()
    );
    let rows: BTreeSet<(String, String)> = LANDINGS
        .iter()
        .map(|(t, text, _)| ((*t).to_string(), (*text).to_string()))
        .collect();
    let unrowed: Vec<_> = internal
        .iter()
        .filter(|(t, text)| {
            !rows
                .iter()
                .any(|(rt, rtext)| rt == t && text.starts_with(rtext))
        })
        .collect();
    let stale: Vec<_> = rows
        .iter()
        .filter(|(rt, rtext)| {
            !internal
                .iter()
                .any(|(t, text)| rt == t && text.starts_with(rtext))
        })
        .collect();
    assert!(
        unrowed.is_empty() && stale.is_empty(),
        "homepage links with no row in LANDINGS: {unrowed:#?}\n\
         rows in LANDINGS with no such link on the homepage: {stale:#?}"
    );
    Ok(())
}

/// Each link's landing holds every term its row names.
#[test]
fn every_homepage_link_lands_on_what_it_promises() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for row in LANDINGS {
        let missing = missing_terms(row, &content_page)?;
        if !missing.is_empty() {
            failures.push(format!(
                "{} ({:?}): landing lacks {}",
                row.0,
                row.1,
                missing.join(", ")
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} homepage link(s) land where the reader does not find what the link \
         promised:\n{}",
        failures.len(),
        failures.join("\n")
    );
    Ok(())
}

/// Every absolute link on the homepage is one of the measured, non-redirecting
/// forms in [`EXTERNAL`].
#[test]
fn every_external_homepage_link_is_a_final_url() -> Result<(), TestError> {
    let found: BTreeSet<String> = links(&homepage()?)?
        .into_iter()
        .map(|(t, _)| t)
        .filter(|t| t.starts_with("http"))
        .collect();
    let pinned: BTreeSet<String> = EXTERNAL.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(
        found, pinned,
        "the homepage's absolute links differ from EXTERNAL. Measure the new \
         link with curl, and pin the form that answers 200 with no redirect."
    );
    Ok(())
}

/// The section reader stops at the next heading of the same level, so a term
/// in the following section does not count; the opening reader stops at the
/// first `##`.
#[test]
fn the_landing_reader_holds_a_link_to_its_own_section() -> Result<(), TestError> {
    let md = "+++\ntitle = \"Keys\"\n+++\nIntro about streams.\n\n\
              ## RTP Streams\nLists streams.\n### Columns\nSSRC.\n\
              ## Stream Detail\nPress P to play.\n";
    let page = |_: &str| Some(md.to_string());
    let here: Landing = ("@/k.md#rtp-streams", "x", &["streams", "SSRC"]);
    assert!(missing_terms(&here, &page)?.is_empty());
    let wrong: Landing = ("@/k.md#rtp-streams", "x", &["play"]);
    assert_eq!(missing_terms(&wrong, &page)?, vec!["\"play\"".to_string()]);
    let top: Landing = ("@/k.md", "x", &["play"]);
    assert_eq!(
        missing_terms(&top, &page)?,
        vec!["\"play\" (not in the page's opening section)".to_string()]
    );
    let deep: Landing = ("@/k.md", "x", &["keys", "play"]);
    assert!(missing_terms(&deep, &page)?.is_empty());
    let gone: Landing = ("@/k.md#nowhere", "x", &["a"]);
    assert_eq!(
        missing_terms(&gone, &page)?,
        vec!["no heading in k.md has the slug nowhere".to_string()]
    );
    Ok(())
}

/// A shell `# comment` in a code block does not end a section, the command
/// in the block counts as text the reader reads, and a term that appears only
/// in a link target does not.
#[test]
fn the_landing_reader_reads_code_but_not_link_targets() -> Result<(), TestError> {
    let md = "## A\n```\n# start it\nsipnab -d eth0\n```\nSee [here](play.md).\n## B\nplay\n";
    let page = |_: &str| Some(md.to_string());
    let code: Landing = ("@/k.md#a", "x", &["-d eth0"]);
    assert!(missing_terms(&code, &page)?.is_empty());
    let target: Landing = ("@/k.md#a", "x", &["play"]);
    assert_eq!(missing_terms(&target, &page)?, vec!["\"play\"".to_string()]);
    Ok(())
}
