// SPDX-License-Identifier: MIT OR Apache-2.0

//! Telling a site that is DOWN from a site that is merely STALE.
//!
//! # The outage
//!
//! On 2026-09-11 the origin certificate for sipnab.com expired at 14:10 UTC.
//! The CDN was in a strict SSL mode, refused an origin it could not validate,
//! and returned 526 to every visitor.
//!
//! The release flow had a step for exactly this — *"verify from the live page,
//! not from a green deploy"* — and the command it gave was:
//!
//! ```text
//! curl -s https://sipnab.com/download/ | grep -c <version>
//! ```
//!
//! That prints `0` when the site advertises the wrong version. It also prints
//! `0` when DNS fails, when the connection is refused, when the certificate has
//! expired, when the body is empty, and when the server returns 500. Five
//! situations, one answer, and only one of them is about the release.
//!
//! I ran that check during the outage, got nothing back, and moved on. My own
//! notes say an empty result is not evidence. It was the outage, half an hour
//! old, and it looked exactly like a page that had not deployed yet.
//!
//! # Two certificates, and watching the wrong one is worse than nothing
//!
//! The public name resolves to the CDN, so a check pointed at it reads the
//! EDGE certificate — a different CA, expiring three months later, and
//! perfectly healthy all through the outage. The certificate that expired
//! belongs to the ORIGIN. A watcher aimed at the hostname would have reported
//! 85 days remaining while every visitor got an error page.
//!
//! # And the renewal had been failing silently
//!
//! `website/static/CNAME` named `www.sipnab.com` while GitHub Pages was
//! configured for the apex the site is built for. Every deploy re-set the
//! custom domain, and each change drops the HTTPS certificate. Nothing renewed
//! because nothing was ever allowed to finish.
//!
//! Both scripts here are split into a fetching half that needs a network and a
//! judging half that does not, which is what lets these drive every verdict
//! with no site at all.

#![cfg(feature = "full")]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Run one script's `--classify` half, returning `(exit code, output)`.
fn classify(script: &str, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    let mut cmd = Command::new("sh");
    cmd.arg(repo().join(script))
        .arg("--classify")
        .args(args)
        .current_dir(repo())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn the classifier");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write");
    }
    let out = child.wait_with_output().expect("the classifier finishes");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

/// A response: a status line, then a body.
fn response(status: &str, body: &str) -> String {
    format!("{status}\n{body}")
}

/// A body that looks like the download page.
fn download_page(version: &str) -> String {
    format!("<h1>Download</h1><p>sipnab {version}</p><p>sha256 checksums below</p>")
}

// ── The distinction the old check could not make ────────────────────────────

/// A healthy page naming the wrong version is STALE, and says what to do.
#[test]
fn a_healthy_page_with_the_wrong_version_is_stale() {
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response("200", &download_page("0.5.165"))),
    );
    assert_eq!(code, 1, "a stale page was not reported as stale:\n{out}");
    assert!(out.contains("STALE"), "{out}");
    assert!(
        out.contains("advertisement commit"),
        "the stale verdict does not say what to do about it:\n{out}"
    );
}

/// An unreachable host is a different verdict, with a different exit code.
///
/// The whole point. `curl | grep -c` gave `0` for this and for the stale case
/// above, and the operator response differs completely.
#[test]
fn an_unreachable_host_is_not_reported_as_a_stale_page() {
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response("000", "")),
    );
    assert_eq!(code, 2, "an unreachable host was misjudged:\n{out}");
    assert!(out.contains("UNREACHABLE"), "{out}");
    assert!(
        !out.contains("STALE"),
        "an unreachable host was also called stale, which is the conflation \
         this file exists for:\n{out}"
    );
}

/// The exact status this outage produced is named as an origin certificate.
///
/// 526 is not a generic server error. It says the edge is healthy and cannot
/// validate the thing behind it, which points at a CDN setting rather than at
/// anything in this repository.
#[test]
fn a_526_is_named_as_an_origin_certificate_problem() {
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response("526", "<html>error 526</html>")),
    );
    assert_eq!(code, 3, "526 was not given the TLS verdict:\n{out}");
    assert!(out.contains("TLS"), "{out}");
    assert!(
        out.to_lowercase().contains("expired"),
        "the verdict does not name the usual cause:\n{out}"
    );
    assert!(
        out.contains("self-sustaining") || out.contains("cannot while"),
        "the verdict does not explain why this state does not fix itself, \
         which is the part an operator needs:\n{out}"
    );
}

/// A success status with an empty body is never a pass.
///
/// The exact shape I read as nothing during the outage.
#[test]
fn an_empty_body_is_never_scored_as_a_pass() {
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response("200", "")),
    );
    assert_eq!(code, 5, "an empty body was not called out:\n{out}");
    assert!(out.contains("EMPTY"), "{out}");
    assert!(
        out.contains("grep"),
        "the verdict does not say why this is different from a missing \
         version, which is the mistake it exists to prevent:\n{out}"
    );
}

/// An ordinary server error is not read as a missing version.
#[test]
fn a_server_error_is_not_read_as_a_missing_version() {
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response("503", "<html>maintenance</html>")),
    );
    assert_eq!(code, 4, "a 503 was misjudged:\n{out}");
    assert!(out.contains("HTTP"), "{out}");
}

/// A version found on an ERROR page is not a pass.
///
/// A CDN interstitial carries the hostname, and a cached error can carry
/// anything. Matching a version string in one would be a match on somebody
/// else's document.
#[test]
fn a_version_inside_an_error_page_does_not_count() {
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response(
            "526",
            "<html>sipnab.com 0.5.166 is temporarily unavailable</html>",
        )),
    );
    assert_eq!(
        code, 3,
        "a version inside an error page was accepted:\n{out}"
    );
    assert!(!out.contains("OK:"), "{out}");
}

/// A 200 whose body is not the download page is refused.
///
/// A parked page, a redirect stub, or a CDN cache of something else can return
/// 200 and contain a version string by accident.
#[test]
fn a_page_that_is_not_the_download_page_is_refused() {
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response("200", "<html>0.5.166 parked domain</html>")),
    );
    assert_eq!(code, 5, "an unrelated page was accepted:\n{out}");
    assert!(out.contains("EMPTY"), "{out}");
}

/// The healthy case passes, so none of the above is a blanket refusal.
///
/// The positive control. Without it every test here passes on a script that
/// refuses everything — which would make the release check useless in the
/// quietest possible way.
#[test]
fn a_healthy_page_naming_the_version_passes() {
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response("200", &download_page("0.5.166"))),
    );
    assert_eq!(code, 0, "a healthy page was refused:\n{out}");
    assert!(out.contains("OK"), "{out}");
}

/// Every verdict has its own exit code.
///
/// Scripted callers branch on the number, not the text. Two situations sharing
/// a code is the original defect in a new costume.
#[test]
fn every_verdict_has_a_distinct_exit_code() {
    let cases = [
        (response("200", &download_page("0.5.166")), 0),
        (response("200", &download_page("0.5.165")), 1),
        (response("000", ""), 2),
        (response("526", "x"), 3),
        (response("503", "x"), 4),
        (response("200", ""), 5),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (body, want) in cases {
        let (code, out) = classify(
            "scripts/verify-site-advertises.sh",
            &["0.5.166"],
            Some(&body),
        );
        assert_eq!(code, want, "wrong code for {body:?}:\n{out}");
        assert!(seen.insert(code), "exit code {code} is used twice");
    }
    assert_eq!(
        seen.len(),
        6,
        "six situations must have six codes: {seen:?}"
    );
}

// ── The certificate watcher ─────────────────────────────────────────────────

/// Plenty of time left is a pass.
#[test]
fn a_certificate_with_time_left_passes() {
    let (code, out) = classify("scripts/check-cert-expiry.sh", &["60"], None);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("OK"), "{out}");
}

/// Inside the margin says renewal has ALREADY failed.
///
/// The wording matters more than the threshold. Automatic renewal runs at 30
/// days remaining, so being inside a 21-day margin is not "renewal is due" —
/// it is "renewal is not happening", and those prompt different actions.
#[test]
fn inside_the_margin_says_renewal_has_already_failed() {
    let (code, out) = classify("scripts/check-cert-expiry.sh", &["7"], None);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("EXPIRING"), "{out}");
    assert!(
        out.contains("ALREADY failed"),
        "the warning reads as a routine reminder rather than a fault:\n{out}"
    );
}

/// An expired certificate is its own verdict, not merely an expiring one.
#[test]
fn an_expired_certificate_is_told_apart_from_an_expiring_one() {
    let (expiring, _) = classify("scripts/check-cert-expiry.sh", &["3"], None);
    let (expired, out) = classify("scripts/check-cert-expiry.sh", &["-1"], None);
    assert_ne!(
        expiring, expired,
        "expiring and expired share an exit code, so a caller cannot tell an \
         outage from a warning"
    );
    assert_eq!(expired, 2, "{out}");
    assert!(out.contains("EXPIRED"), "{out}");
}

/// A certificate that could not be read is never a pass.
///
/// The same rule as the empty body: no answer is not a good answer. A watcher
/// that scored an unreadable certificate as healthy would go green the moment
/// the host stopped responding, which is precisely when it should shout.
#[test]
fn an_unreadable_certificate_is_never_a_pass() {
    for bad in ["", "unknown", "n/a"] {
        let (code, out) = classify("scripts/check-cert-expiry.sh", &[bad], None);
        assert_eq!(code, 3, "{bad:?} was not reported as unreadable:\n{out}");
        assert!(out.contains("UNKNOWN"), "{out}");
    }
}

/// The margin is a boundary, and both sides of it are pinned.
///
/// An off-by-one here is a watcher that fires a day late, which for a
/// certificate is the difference between a warning and an outage.
#[test]
fn the_expiry_margin_is_exact_at_its_boundary() {
    let (inside, _) = classify("scripts/check-cert-expiry.sh", &["21", "21"], None);
    assert_eq!(inside, 1, "21 days under a 21-day margin must warn");
    let (outside, _) = classify("scripts/check-cert-expiry.sh", &["22", "21"], None);
    assert_eq!(outside, 0, "22 days under a 21-day margin must pass");
}

// ── Coupling, so none of this can quietly stop being used ───────────────────

/// The watcher is installed on a schedule, not run when somebody remembers.
///
/// A certificate expires on a date, so a check that only runs when a human
/// thinks of it is a check that runs after the outage. This one is scheduled,
/// and it also runs on changes to itself so a broken watcher is caught by the
/// thing it watches rather than the next morning.
#[test]
fn the_certificate_watcher_runs_on_a_schedule() {
    let wf = std::fs::read_to_string(repo().join(".github/workflows/cert-expiry.yml"))
        .expect("the scheduled workflow is in the tree");
    assert!(wf.contains("schedule:"), "the watcher is not scheduled");
    assert!(wf.contains("cron:"), "the schedule names no time");
    assert!(
        wf.contains("check-cert-expiry.sh"),
        "the scheduled job does not run the check"
    );
    assert!(
        wf.contains("SIPNAB_ORIGIN"),
        "the scheduled job never checks the ORIGIN certificate, which is the \
         one that expired while the edge stayed healthy"
    );
}

/// The release flow points at the checker, not at a bare grep.
///
/// The instruction that missed the outage is the one a person follows at
/// release time. Leaving it as `curl | grep -c` while a better check exists
/// beside it means the better one is never run.
#[test]
fn the_release_flow_points_at_the_checker_rather_than_a_bare_grep() {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-push"))
        .expect(".githooks/pre-push is in the tree");
    assert!(
        hook.contains("verify-site-advertises.sh"),
        "the release prompt does not name the check that can tell a down site \
         from a stale one"
    );
    let bare = hook
        .lines()
        .filter(|l| l.contains("grep -c") && l.contains("sipnab.com"))
        .collect::<Vec<_>>();
    assert!(
        bare.is_empty(),
        "the release prompt still tells an operator to run a bare grep, which \
         scores an outage and a stale page identically: {bare:?}"
    );
}

/// The published CNAME matches the site the build is generated for.
///
/// The mismatch that broke renewal, checked where it cannot drift back.
/// `base_url` is what the site is built for and CNAME is what Pages is told;
/// when they disagree, every deploy re-sets the custom domain and each change
/// drops the certificate.
#[test]
fn the_published_cname_matches_the_base_url() {
    let cname = std::fs::read_to_string(repo().join("website/static/CNAME"))
        .expect("the CNAME is in the tree")
        .trim()
        .to_string();
    let config = std::fs::read_to_string(repo().join("website/config.toml"))
        .expect("the site config is in the tree");
    let base = config
        .lines()
        .find_map(|l| l.strip_prefix("base_url = \""))
        .and_then(|r| r.strip_suffix('"'))
        .and_then(|u| u.strip_prefix("https://"))
        .map(|h| h.trim_end_matches('/').to_string())
        .expect("base_url is an https URL");
    assert_eq!(
        cname, base,
        "the published CNAME and base_url name different hosts. Every deploy \
         then re-sets the Pages custom domain, and each change drops the HTTPS \
         certificate — which is how the origin certificate came to expire \
         unrenewed"
    );
}
