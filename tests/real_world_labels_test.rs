// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The message labels in `docs/real-world-captures.md` are the ones sipnab
//! prints for those captures today.
//!
//! The page rewrites every address and identifier, so its blocks cannot be
//! compared to a run byte for byte. What it keeps as measured, the time and
//! the ports of each message, identifies each line, and the label after them
//! (`INVITE (SDP)`, `100 trying -- your call is important to us`) is sipnab's
//! own output. This test runs sipnab over each capture a block names and
//! requires each documented label on the message with that time and those
//! ports.
//!
//! The captures are private and never in the repository. Point
//! `SIPNAB_REAL_WORLD_CAPTURES` at a directory holding them under the names
//! the page uses (`trunk.pcap0`, `pbx.pcap4`, `inbound.pcap`); unset, the test
//! says so and checks nothing.
#![cfg(feature = "native")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// `HH:MM:SS.mmm SRC:PORT -> DST:PORT LABEL TRANSPORT`, the per-message
/// summary line: (time, source port, destination port, the rest).
fn summary_line(line: &str) -> Option<(String, String, String, String)> {
    let re = regex::Regex::new(r"^(\d\d:\d\d:\d\d\.\d{3}) \S+:(\d+) -> \S+:(\d+) (.+)$").ok()?;
    let c = re.captures(line)?;
    Some((
        c[1].to_string(),
        c[2].to_string(),
        c[3].to_string(),
        c[4].to_string(),
    ))
}

/// One output block of the page: the capture its command reads, and the
/// summary lines it shows.
struct Block {
    line: usize,
    capture: String,
    lines: Vec<(String, String, String, String)>,
}

/// Every output block that shows summary lines, with the capture named by the
/// `-I` of the command block before it.
fn blocks(page: &str) -> Result<Vec<Block>, TestError> {
    let mut out = Vec::new();
    let mut command = String::new();
    let mut fence: Option<(usize, String, Vec<String>)> = None;
    for (n, line) in page.lines().enumerate() {
        if let Some(rest) = line.strip_prefix("```") {
            match fence.take() {
                None => fence = Some((n + 1, rest.to_string(), Vec::new())),
                Some((start, lang, body)) => {
                    if lang == "bash" || lang == "sh" {
                        command = body.join("\n");
                    } else {
                        let lines: Vec<_> = body.iter().filter_map(|l| summary_line(l)).collect();
                        if !lines.is_empty() {
                            let capture = command
                                .split_whitespace()
                                .skip_while(|w| *w != "-I")
                                .nth(1)
                                .ok_or_else(|| {
                                    format!("the block at line {start} follows no -I command")
                                })?
                                .to_string();
                            out.push(Block {
                                line: start,
                                capture,
                                lines,
                            });
                        }
                    }
                }
            }
        } else if let Some((_, _, body)) = fence.as_mut() {
            body.push(line.to_string());
        }
    }
    Ok(out)
}

/// A message's place in a capture: (time, source port, destination port).
type MessageKey = (String, String, String);

/// Every label sipnab printed, by the place of its message.
type LabelsByKey = BTreeMap<MessageKey, Vec<String>>;

/// The labels sipnab prints for `capture`, keyed by (time, source port,
/// destination port).
fn labels(capture: &Path) -> Result<LabelsByKey, TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I"])
        .arg(capture)
        .args(["--portrange", "1-65535", "--quiet"])
        .output()?;
    // A rotating capture ring cuts its files mid-packet, and sipnab exits 1
    // for a file it could not read in full (docs/cli-reference.md, "Exit
    // codes"), after printing every message it did read. That is the one
    // non-zero exit this comparison accepts.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let truncated = out.status.code() == Some(1) && stderr.contains("stopped early");
    assert!(
        out.status.success() || truncated,
        "sipnab over {} exited {:?}: {stderr}",
        capture.display(),
        out.status.code()
    );
    let mut map = LabelsByKey::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((t, sp, dp, label)) = summary_line(line) {
            map.entry((t, sp, dp)).or_default().push(label);
        }
    }
    Ok(map)
}

#[test]
fn real_world_page_labels_are_the_ones_sipnab_prints() -> Result<(), TestError> {
    let Some(dir) = std::env::var_os("SIPNAB_REAL_WORLD_CAPTURES").map(PathBuf::from) else {
        eprintln!(
            "SKIPPED: SIPNAB_REAL_WORLD_CAPTURES is unset, so the labels in \
             docs/real-world-captures.md were not compared to a run"
        );
        return Ok(());
    };
    let page = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/real-world-captures.md"
    ))?;
    let mut runs = BTreeMap::new();
    let mut wrong = Vec::new();
    let mut checked = 0;
    for block in blocks(&page)? {
        let path = dir.join(&block.capture);
        assert!(
            path.is_file(),
            "{} is not in {}: the block at line {} reads it",
            block.capture,
            dir.display(),
            block.line
        );
        if !runs.contains_key(&block.capture) {
            runs.insert(block.capture.clone(), labels(&path)?);
        }
        let run = &runs[&block.capture];
        for (t, sp, dp, label) in &block.lines {
            checked += 1;
            match run.get(&(t.clone(), sp.clone(), dp.clone())) {
                Some(got) if got.contains(label) => {}
                got => wrong.push(format!(
                    "line in the block at {}: {t} :{sp} -> :{dp} reads {label:?}; sipnab prints {got:?}",
                    block.line
                )),
            }
        }
    }
    assert!(checked > 0, "the page shows no summary line to compare");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    Ok(())
}

/// The block reader finds a block's capture and its summary lines, and skips
/// a block with none.
#[test]
fn the_block_reader_pairs_each_block_with_its_capture() -> Result<(), TestError> {
    let page = "```bash\nsipnab -N -I a.pcap --quiet\n```\n\n```text\n\
                12:00:00.000 192.0.2.1:5060 -> 192.0.2.2:5070 INVITE (SDP) UDP\n\
                Via: SIP/2.0/UDP 192.0.2.1:5060\n```\n\n```text\nno summary here\n```\n";
    let found = blocks(page)?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].capture, "a.pcap");
    assert_eq!(
        found[0].lines,
        [(
            "12:00:00.000".to_string(),
            "5060".to_string(),
            "5070".to_string(),
            "INVITE (SDP) UDP".to_string()
        )]
    );
    Ok(())
}
