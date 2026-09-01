// SPDX-License-Identifier: MIT OR Apache-2.0

//! The captures the site SHOWS and the capture it OFFERS must be one capture.
//!
//! A visitor watches the homepage animation, clicks through to `/analyze`, and
//! presses "Load a sample call". Until 2026-09-01 those were three different
//! captures: the hero still ran `register-invite-reinvite-bye.pcap`, the
//! animation ran `sip-rtp-g711.pcap`, and the analyze page fetched
//! `demos/sample-call.pcap`. Nothing failed, because nothing compared them.
//!
//! That is the shape of the defect, and it is worth stating precisely: every
//! individual asset was valid, every tape rendered, every gate was green. The
//! only thing wrong was an AGREEMENT between files that no rule expressed. A
//! reviewer cannot see it either — the three facts live in a `.tape`, a
//! `.html` template and a `.js` fetch, and no diff puts them side by side.
//!
//! These tests express that agreement. They are cheap, they read three files,
//! and they replace a claim somebody has to remember to re-check by hand.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = repo().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every `.tape` under `demos/`, as (name, contents).
fn tapes() -> Vec<(String, String)> {
    let dir = repo().join("demos");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir)
        .expect("demos/ is readable")
        .flatten()
    {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "tape") {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.push((name, std::fs::read_to_string(&p).unwrap_or_default()));
        }
    }
    out.sort();
    out
}

/// The capture path a tape drives, read off its `Type "sipnab -I …"` line.
///
/// The `-I` argument and nothing else: a tape may mention other paths in its
/// comments, and a scan that matched those would report a capture the
/// recording never opened.
fn capture_of(tape: &str) -> Option<String> {
    for line in tape.lines() {
        let line = line.trim();
        if line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("Type \"") else {
            continue;
        };
        let Some((cmd, _)) = rest.split_once('"') else {
            continue;
        };
        let mut parts = cmd.split_whitespace();
        while let Some(tok) = parts.next() {
            if tok == "-I" {
                return parts.next().map(str::to_owned);
            }
        }
    }
    None
}

/// The capture `/analyze` fetches behind "Load a sample call".
fn analyze_sample() -> String {
    let js = read("website/static/js/analyze.js");
    let at = js
        .find("/demos/")
        .expect("analyze.js fetches a sample capture from /demos/");
    let tail = &js[at..];
    let end = tail
        .find(['"', '\''])
        .expect("the fetch path is a quoted literal");
    tail[..end].trim_start_matches('/').to_string()
}

/// Which tape renders the animation the hero swaps to.
///
/// The homepage shows a still and replaces it with an animation once that
/// decodes, so the ANIMATION is what a visitor actually watches. Reading the
/// template rather than hard-coding the name, so renaming the asset moves this
/// test with it instead of leaving it pinned to a file nobody serves.
fn hero_animation_asset() -> String {
    let html = read("website/templates/index.html");
    let at = html
        .find("var animated =")
        .expect("index.html swaps the hero for an animation");
    let tail = &html[at..];
    let open = tail.find("path='").expect("the swap names an asset path") + 6;
    let rest = &tail[open..];
    let end = rest.find('\'').expect("an unterminated asset path");
    rest[..end].to_string()
}

/// The tape whose `Output` produces a given static asset.
fn tape_producing(asset: &str) -> Option<(String, String)> {
    let stem = Path::new(asset).file_stem()?.to_string_lossy().into_owned();
    tapes().into_iter().find(|(_, body)| {
        body.lines().any(|l| {
            let l = l.trim();
            l.starts_with("Output ") && l.contains(&stem)
        })
    })
}

/// The homepage animation and the analyze sample are ONE capture.
///
/// The whole point. A visitor who watches the homepage and then presses "Load
/// a sample call" must be given the call they were just shown; being handed a
/// different one makes the demo a promise the page does not keep.
#[test]
fn the_homepage_animation_and_the_analyze_sample_use_one_capture() {
    let asset = hero_animation_asset();
    let (tape_name, tape) =
        tape_producing(&asset).unwrap_or_else(|| panic!("no tape produces {asset}"));
    let shown = capture_of(&tape)
        .unwrap_or_else(|| panic!("{tape_name} drives no capture: it has no `-I` argument"));
    let offered = analyze_sample();

    assert!(
        shown.ends_with(&offered) || offered.ends_with(&shown),
        "the homepage animation shows {shown} ({tape_name}) and /analyze offers \
         {offered}. A visitor who watches the video and clicks through is handed \
         a different call than the one they just saw."
    );
}

/// The hero still and the hero animation are ONE capture.
///
/// The still is what loads first and the animation replaces it. Sourcing them
/// from different captures makes the page appear to cut between two calls, and
/// it is the exact half-fix that shipped on 2026-08-31: the still was
/// retargeted and the animation was not.
#[test]
fn the_hero_still_and_the_hero_animation_use_one_capture() {
    let still = capture_of(&read("demos/hero.tape")).expect("hero.tape drives a capture");
    let anim_asset = hero_animation_asset();
    let (anim_tape, body) =
        tape_producing(&anim_asset).unwrap_or_else(|| panic!("no tape produces {anim_asset}"));
    let anim = capture_of(&body).unwrap_or_else(|| panic!("{anim_tape} drives no capture"));

    assert_eq!(
        still, anim,
        "the hero still comes from {still} and the animation it swaps to comes \
         from {anim} ({anim_tape}). The page would cut between two different \
         calls as the animation loads."
    );
}

/// Every tape drives a capture that is actually there.
///
/// A tape naming a moved or deleted capture still renders: sipnab prints an
/// error and VHS records the error. The result is a plausible-looking demo of
/// nothing, and only a human looking at the output would notice.
#[test]
fn every_demo_tape_drives_a_capture_that_exists() {
    let mut missing = Vec::new();
    let mut checked = 0;
    for (name, body) in tapes() {
        let Some(cap) = capture_of(&body) else {
            continue; // a tape that opens no capture is fine; `mcp-*.tape` do not
        };
        checked += 1;
        if !repo().join(&cap).is_file() {
            missing.push(format!("  {name}: drives {cap}, which is not in the tree"));
        }
    }
    assert!(
        checked >= 5,
        "only {checked} tape(s) name a capture; the `-I` scan has stopped \
         matching and this gate proves nothing"
    );
    assert!(
        missing.is_empty(),
        "these tapes drive a capture that is not there. VHS would record \
         sipnab's error and ship it as a demo:\n{}",
        missing.join("\n")
    );
}

/// No tape depends on a capture the repository does not ship.
///
/// A tape driving an ignored or untracked file renders here and nowhere else.
/// The corpus rule makes this concrete: real customer traffic can never be
/// committed, so a demo built on it can never be reproduced by anyone.
#[test]
fn no_demo_tape_drives_an_uncommitted_capture() {
    let tracked = std::process::Command::new("git")
        .args(["ls-files"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    let tracked = String::from_utf8_lossy(&tracked.stdout);
    let tracked: std::collections::BTreeSet<&str> = tracked.lines().collect();

    let mut untracked = Vec::new();
    for (name, body) in tapes() {
        let Some(cap) = capture_of(&body) else {
            continue;
        };
        if !tracked.contains(cap.as_str()) {
            untracked.push(format!("  {name}: drives {cap}, which git does not track"));
        }
    }
    assert!(
        untracked.is_empty(),
        "these tapes drive a capture nobody else can obtain, so nobody else can \
         re-render them:\n{}",
        untracked.join("\n")
    );
}

/// The capture `/analyze` offers is one the site actually ships.
///
/// The page fetches it at runtime. A path that resolves on this machine and
/// 404s in production turns the one button a first-time visitor presses into a
/// dead end.
#[test]
fn the_analyze_sample_capture_is_shipped() {
    let offered = analyze_sample();
    let on_disk = repo().join("website/static").join(&offered);
    assert!(
        on_disk.is_file(),
        "/analyze fetches /{offered} and website/static/{offered} does not \
         exist; the sample button would 404"
    );
    let bytes = std::fs::metadata(&on_disk).map(|m| m.len()).unwrap_or(0);
    assert!(
        bytes > 1024,
        "the offered sample is {bytes} bytes, which cannot be a capture worth \
         demonstrating"
    );
}

/// Every tape writes its output where the site serves from.
///
/// A tape whose `Output` lands outside `website/static/demos/` renders
/// something no page can show, and the render still reports success.
#[test]
fn every_demo_tape_writes_into_the_served_directory() {
    let mut stray = Vec::new();
    let mut outputs = 0;
    for (name, body) in tapes() {
        for line in body.lines() {
            let line = line.trim();
            let Some(out) = line.strip_prefix("Output ") else {
                continue;
            };
            outputs += 1;
            let out = out.trim();
            // The hero writes a throwaway gif beside the tape and screenshots
            // the asset separately; that intermediate is deleted by the rule.
            if !out.starts_with("website/static/demos/") && !out.starts_with("demos/.") {
                stray.push(format!("  {name}: Output {out}"));
            }
        }
    }
    assert!(
        outputs >= 5,
        "only {outputs} Output line(s) found; the scan is wrong"
    );
    assert!(
        stray.is_empty(),
        "these tapes render to a path the site does not serve:\n{}",
        stray.join("\n")
    );
}

/// The scan reads a real tree.
///
/// Anti-vacuity for every filter above. Each one narrows, and a narrowing that
/// reaches zero exits 0 forever while looking exactly like agreement.
#[test]
fn the_tape_scan_found_a_plausible_tree() {
    let all = tapes();
    assert!(
        all.len() >= 8,
        "only {} tape(s) found under demos/; the walk is wrong",
        all.len()
    );
    let driving = all.iter().filter(|(_, b)| capture_of(b).is_some()).count();
    assert!(
        driving >= 5,
        "only {driving} tape(s) drive a capture; the `-I` extraction is wrong"
    );
    assert!(
        driving < all.len(),
        "every tape drives a capture, which means the extraction is matching \
         something it should not -- the mcp-example tapes open none"
    );
    assert!(
        !analyze_sample().is_empty(),
        "the analyze sample path came back empty"
    );
    assert!(
        !hero_animation_asset().is_empty(),
        "the hero animation asset came back empty"
    );
}
