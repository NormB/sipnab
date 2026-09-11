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

// ── A number that is not a number ───────────────────────────────────────────

/// Garbage in the day count is UNKNOWN, never a pass.
///
/// Found by probing the classifier the day it shipped. The guard was a shell
/// character class, `*[!0-9-]*`, which admits a `-` ANYWHERE rather than only
/// at the front — so `1-2`, `12-` and a bare `-` all walked past it. `[` then
/// refused them with "Illegal number", and because a failing test inside an
/// `if` condition is exempt from `set -e`, both comparisons fell through to
/// the last line of the function, which prints OK and returns 0.
///
/// So the one input the script exists to refuse — a certificate it could not
/// read — came out as the healthiest verdict it has, with the diagnosis on
/// stderr where no exit code carries it.
#[test]
fn a_day_count_that_is_not_a_number_is_never_scored_as_healthy() {
    for bad in ["1-2", "12-", "-", "--5", "3-4-5"] {
        let (code, out) = classify("scripts/check-cert-expiry.sh", &[bad], None);
        assert_eq!(
            code, 3,
            "{bad:?} was scored {code} rather than UNKNOWN. An unreadable \
             certificate must never come out as a pass:\n{out}"
        );
        assert!(out.contains("UNKNOWN"), "{bad:?}:\n{out}");
    }
}

/// The shell's own error is not allowed to be the diagnosis.
///
/// "Illegal number" on stderr with exit 0 is the worst shape a check can have:
/// a human reading a terminal sees a problem and a caller reading `$?` sees
/// success. CI reads `$?`.
#[test]
fn a_shell_error_never_stands_in_for_a_verdict() {
    let (code, out) = classify("scripts/check-cert-expiry.sh", &["1-2"], None);
    assert_ne!(code, 0, "a shell diagnostic came back as success:\n{out}");
    assert!(
        !out.contains("Illegal number") && !out.to_lowercase().contains("not found"),
        "the script leaked a shell diagnostic instead of naming its own \
         verdict:\n{out}"
    );
}

/// A mistyped margin is refused rather than quietly ignored.
///
/// The margin is the second argument, so it is an operator's typo away from
/// being unusable — and it reaches the same `[` comparison. A watcher whose
/// threshold silently stopped working would report OK on the day the
/// certificate expired, which is the failure this whole file exists for.
#[test]
fn a_malformed_margin_is_refused_rather_than_ignored() {
    for bad in ["21x", "", "two"] {
        let (code, out) = classify("scripts/check-cert-expiry.sh", &["30", bad], None);
        assert_eq!(
            code, 3,
            "a margin of {bad:?} was accepted and the check still reported \
             {code}:\n{out}"
        );
        assert!(out.contains("UNKNOWN"), "{bad:?}:\n{out}");
    }
}

// ── The watcher itself, and the ten the outage bought ───────────────────────

/// Run a script for real, with an environment, returning `(exit code, output)`.
fn run(script: &str, args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let mut cmd = Command::new("sh");
    cmd.arg(repo().join(script))
        .args(args)
        .current_dir(repo())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("the script runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

/// The workflow file, read once per test that needs it.
fn watcher() -> String {
    std::fs::read_to_string(repo().join(".github/workflows/cert-expiry.yml"))
        .expect("the scheduled workflow is in the tree")
}

/// The watcher bounds its own runtime.
///
/// Four network round trips, and a job that hangs on an unreachable host would
/// sit until GitHub's six-hour default and report nothing. Silence is the
/// failure mode this workflow exists to break, so it may not produce silence
/// of its own.
#[test]
fn the_watcher_bounds_its_own_runtime() {
    let wf = watcher();
    let minutes = wf
        .lines()
        .find_map(|l| l.trim().strip_prefix("timeout-minutes:"))
        .map(|v| v.trim().parse::<u32>().expect("a number of minutes"))
        .expect("the watcher sets no timeout, so a hang runs for six hours");
    assert!(
        minutes > 0 && minutes <= 30,
        "a {minutes}-minute bound on four round trips is not a bound"
    );
}

/// BOTH certificates, and only one of them with an origin.
///
/// Watching the public name alone is worse than not watching: it reads the
/// EDGE certificate, which was healthy with 85 days left all through the
/// outage. Watching only the origin loses the edge. The workflow runs the
/// check twice and exactly one run carries `SIPNAB_ORIGIN`.
#[test]
fn the_watcher_reads_both_certificates() {
    let wf = watcher();
    let runs = wf
        .lines()
        .filter(|l| l.contains("sh scripts/check-cert-expiry.sh"))
        .count();
    assert_eq!(
        runs, 2,
        "the watcher runs the certificate check {runs} time(s); it needs one \
         for the edge and one for the origin"
    );
    let origins = wf.matches("SIPNAB_ORIGIN:").count();
    assert_eq!(
        origins, 1,
        "{origins} of the runs name an origin. Exactly one must: with none it \
         reads the edge twice, with two it never reads the edge at all"
    );
}

/// The origin it checks is a GitHub Pages address.
///
/// Pointing this at the CDN, or at a stale address, restores the very blind
/// spot the second check exists to cover — and it would stay green, because
/// SNI means some certificate always comes back.
#[test]
fn the_origin_the_watcher_checks_is_a_pages_address() {
    let wf = watcher();
    let addr = wf
        .lines()
        .find_map(|l| l.trim().strip_prefix("SIPNAB_ORIGIN:"))
        .map(|v| v.trim().to_string())
        .expect("the watcher names no origin address");
    const PAGES: [&str; 4] = [
        "185.199.108.153",
        "185.199.109.153",
        "185.199.110.153",
        "185.199.111.153",
    ];
    assert!(
        PAGES.contains(&addr.as_str()),
        "{addr} is not one of GitHub Pages' addresses, so the 'origin' check \
         is reading somebody else's certificate: {PAGES:?}"
    );
}

/// An origin that does not answer is UNKNOWN, not a pass.
///
/// The fetching half, driven against a port with nothing behind it. A watcher
/// that scored an unreachable origin as healthy would go green at the exact
/// moment the origin disappeared.
#[test]
fn an_origin_that_does_not_answer_is_never_a_pass() {
    let (code, out) = run(
        "scripts/check-cert-expiry.sh",
        &["sipnab.com"],
        &[("SIPNAB_ORIGIN", "127.0.0.1")],
    );
    assert_eq!(code, 3, "an unreachable origin was scored {code}:\n{out}");
    assert!(out.contains("UNKNOWN"), "{out}");
}

/// The watcher also asks whether the site is serving the release.
///
/// A healthy certificate and a stale page are different problems with
/// different fixes, and the check this replaced scored both as `0`. Watching
/// only the dates would have caught the outage a fortnight early and still
/// never noticed a deploy that did not land.
#[test]
fn the_watcher_also_confirms_the_site_advertises_the_release() {
    let wf = watcher();
    assert!(
        wf.contains("verify-site-advertises.sh"),
        "the daily job reads certificates and never fetches the page"
    );
    assert!(
        wf.contains("published_version"),
        "the job does not read which release the site is supposed to be \
         serving, so it cannot tell whether it is"
    );
}

/// The watcher runs when the thing it depends on changes.
///
/// The CNAME and `base_url` are the pair whose disagreement broke renewal.
/// Catching that pair on the commit that changes it is the difference between
/// a failed push and thirty silent days.
#[test]
fn the_watcher_runs_when_the_domain_configuration_changes() {
    let wf = watcher();
    for path in [
        "website/static/CNAME",
        "website/config.toml",
        "scripts/check-cert-expiry.sh",
    ] {
        assert!(
            wf.contains(path),
            "a change to {path} does not run the watcher, so a broken watcher \
             or a re-broken domain is found at 07:10 the next morning"
        );
    }
}

/// A redirect is not a healthy page.
///
/// `2??` passes and everything else is judged. A 301 to a parked domain, or a
/// CDN redirect loop, answers with a status and no download page — and the
/// bare grep counted it as "the version is not there".
#[test]
fn a_redirect_is_not_read_as_a_missing_version() {
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response("301", "<html>moved</html>")),
    );
    assert_eq!(code, 4, "a 301 was scored {code}:\n{out}");
    assert!(
        !out.contains("STALE"),
        "a redirect is not a stale page:\n{out}"
    );
}

/// A CDN that cannot reach the origin is not a server error.
///
/// 521, 522 and 523 say the edge is healthy and the thing behind it is not,
/// which sends an operator somewhere completely different from a 500. The
/// wording has to carry that, because the exit code alone cannot.
#[test]
fn a_cdn_origin_failure_is_not_confused_with_a_server_error() {
    for status in ["521", "522", "523"] {
        let (code, out) = classify(
            "scripts/verify-site-advertises.sh",
            &["0.5.166"],
            Some(&response(status, "x")),
        );
        assert_eq!(code, 4, "{status}:\n{out}");
        assert!(
            out.contains("origin"),
            "{status} does not say the origin is the unreachable half:\n{out}"
        );
    }
    let (code, out) = classify(
        "scripts/verify-site-advertises.sh",
        &["0.5.166"],
        Some(&response("500", "x")),
    );
    assert_eq!(code, 4, "{out}");
    assert!(
        !out.contains("origin"),
        "an ordinary server error is being described as an origin problem, \
         which sends the reader to the wrong system:\n{out}"
    );
}

/// Zero is reached by exactly one road.
///
/// The property underneath every verdict here: the check may only say "yes"
/// when it actually saw the version on a page that looked like the download
/// page. Every other status, and every other body, is some flavor of no.
#[test]
fn the_checker_exits_zero_only_when_it_found_the_version() {
    let mut zeros = 0;
    for status in ["000", "200", "204", "301", "404", "500", "521", "526"] {
        for body in [
            "",
            "x",
            &download_page("0.5.165"),
            &download_page("0.5.166"),
        ] {
            let (code, _) = classify(
                "scripts/verify-site-advertises.sh",
                &["0.5.166"],
                Some(&response(status, body)),
            );
            let found = status.starts_with('2') && body.contains("0.5.166");
            if code == 0 {
                zeros += 1;
            }
            assert_eq!(
                code == 0,
                found,
                "status {status} with body {body:?} exited {code}"
            );
        }
    }
    assert_eq!(
        zeros, 2,
        "the only healthy cases are the two success statuses carrying the \
         download page with the version on it"
    );
}

/// The CNAME is a bare hostname.
///
/// GitHub Pages reads the file literally. A scheme, a path or a second line
/// makes it a domain that does not exist, the custom domain is dropped, and
/// the certificate goes with it — the same ending as the mismatch, by a
/// different route.
#[test]
fn the_published_cname_is_a_bare_hostname() {
    let raw = std::fs::read_to_string(repo().join("website/static/CNAME"))
        .expect("the CNAME is in the tree");
    let lines: Vec<_> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "a CNAME file holds one name: {lines:?}");
    let name = lines[0].trim();
    assert_eq!(name, lines[0], "the name carries surrounding whitespace");
    for bad in ["://", "/", " ", ":"] {
        assert!(
            !name.contains(bad),
            "the CNAME is {name:?}, which is not a bare hostname"
        );
    }
    assert!(
        name.contains('.') && !name.starts_with('.') && !name.ends_with('.'),
        "the CNAME is {name:?}"
    );
}

/// The documented release procedure names the checker.
///
/// The pre-push prompt was updated and the document was not, which is how the
/// bare grep survived in the first place: it lived in the place a person reads
/// at release time rather than in a script anybody ran.
#[test]
fn the_documented_release_procedure_names_the_checker() {
    let doc = std::fs::read_to_string(repo().join("docs/internals/build-ci-release.md"))
        .expect("the release document is in the tree");
    assert!(
        doc.contains("verify-site-advertises.sh"),
        "the release procedure never tells the reader how to confirm the site \
         is serving the release, so 'released' stays a green deploy"
    );
    // The old command still appears, as the thing being replaced. That is the
    // point of the paragraph. What may not happen is it appearing in a fence a
    // reader would copy: `text` is a quotation, `sh` is an instruction.
    let mut fence = String::new();
    let mut prescribed: Vec<&str> = Vec::new();
    for line in doc.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("```") {
            fence = if fence.is_empty() {
                rest.trim().to_string()
            } else {
                String::new()
            };
            continue;
        }
        let runnable = matches!(fence.as_str(), "sh" | "bash" | "shell" | "console");
        if runnable && line.contains("grep -c") && line.contains("sipnab.com") {
            prescribed.push(line);
        }
    }
    assert!(
        prescribed.is_empty(),
        "the document offers a bare grep in a fence a reader will copy and \
         run: {prescribed:?}"
    );
}

// ── A count in a commit message is a claim, and claims get checked ──────────

/// Run the claim checker over a message.
fn claim(message: &str, actual: &str) -> (i32, String) {
    let mut child = Command::new("sh")
        .arg(repo().join("scripts/check-test-claim.sh"))
        .arg("--classify")
        .arg(actual)
        .current_dir(repo())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the claim checker");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(message.as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("the checker finishes");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

/// A count spelled as a word is still a number.
///
/// The defect this is for: a commit message here said "Sixteen tests" about a
/// commit that added seventeen. A spelled number does not look like data — it
/// reads as prose, and prose is not checked. It is the one claim about a
/// change a reader cannot verify without the diff in front of them.
#[test]
fn a_count_spelled_as_a_word_is_checked_like_a_number() {
    let message = "Watch the certificate\n\nSeventeen tests, mutation-proven.\n";
    let (agrees, out) = claim(message, "17");
    assert_eq!(agrees, 0, "a correct spelled count was rejected:\n{out}");

    let wrong = "Watch the certificate\n\nSixteen tests, mutation-proven.\n";
    let (disagrees, out) = claim(wrong, "17");
    assert_eq!(
        disagrees, 1,
        "the exact defect walked past the check:\n{out}"
    );
    assert!(out.contains("DISAGREES"), "{out}");
}

/// Digits and words are read the same way, hyphens included.
#[test]
fn a_numeral_and_a_compound_word_agree_with_each_other() {
    for (text, actual) in [
        ("17 tests, mutation-proven.", "17"),
        ("Seventeen tests, mutation-proven.", "17"),
        ("Twenty-one tests, mutation-proven.", "21"),
        ("Ninety-nine tests, mutation-proven.", "99"),
        ("One test, mutation-proven.", "1"),
    ] {
        let (code, out) = claim(text, actual);
        assert_eq!(code, 0, "{text:?} against {actual}:\n{out}");
    }
}

/// Prose that merely mentions tests is not a claim.
///
/// A gate that fired on "these tests" or "8287 automated tests" would be wrong
/// far more often than right, and a gate that cries wolf gets switched off. It
/// reports NO CLAIM, which is a third state with its own exit code rather than
/// a pass wearing a disguise.
#[test]
fn prose_that_merely_mentions_tests_is_not_a_claim() {
    for text in [
        "A change with 8287 automated tests, and all tests are green.",
        "These tests cover the parser.",
        "No tests were harmed.",
        "Refuse a stream link for a media description the peers rejected.",
    ] {
        let (code, out) = claim(text, "4");
        assert_eq!(code, 2, "{text:?} was read as a claim:\n{out}");
        assert!(out.contains("NO CLAIM"), "{out}");
    }
}

/// The push gate checks every commit it is about to send.
///
/// The script on its own is a script nobody runs. This is the coupling that
/// makes the claim a gate, checked at the last moment a message can still be
/// amended.
#[test]
fn the_push_gate_checks_each_message_against_its_diff() {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-push"))
        .expect(".githooks/pre-push is in the tree");
    assert!(
        hook.contains("check-test-claim.sh"),
        "nothing runs the claim checker, so a count in a commit message is \
         still whatever somebody typed"
    );
    // The hook counts the attribute with a grep, so the pattern is escaped
    // there. Matching the escaped form is matching the thing that runs.
    assert!(
        hook.contains(r"#\[test\]"),
        "the hook never counts the tests a commit adds, so it has nothing to \
         compare the claim against"
    );
}

/// The claim is the summary count, not one counted along the way.
///
/// The defect this is for, found by the gate on the commit that introduced it:
/// the message claimed eighteen and the checker read ten, out of a sentence
/// three lines above that counted a subset. A message may legitimately count
/// parts of itself, so "the first number next to the word tests" is not the
/// claim — the summary sentence is.
#[test]
fn the_claim_is_the_summary_count_not_one_counted_along_the_way() {
    let message = "Refuse a day count that is not a number\n\n\
         Two defects, and the ten tests the outage itself bought.\n\n\
         Eighteen tests, mutation-proven: restoring the old class fails two.\n";
    let (code, out) = claim(message, "18");
    assert_eq!(
        code, 0,
        "a subset counted in the body was read as the claim:\n{out}"
    );
    let (wrong, out) = claim(message, "10");
    assert_eq!(
        wrong, 1,
        "the checker agreed with the subset rather than the summary:\n{out}"
    );

    // And when a message carries two summary sentences — an amended one
    // usually does — the later is the one that describes the commit.
    let amended = "x\n\nTwo tests, mutation-proven: a.\n\n\
         Nine tests, mutation-proven: b.\n";
    let (code, out) = claim(amended, "9");
    assert_eq!(code, 0, "the earlier summary won over the later:\n{out}");
}

/// The summary sentence is found wherever the wrapping put it.
///
/// The marker is `, mutation-proven`, not the position: a wrapped message puts
/// the count mid-line and an unwrapped one begins a line with it. Anchoring on
/// the line start instead was tried and reads "Two tests were removed..." as a
/// claim, which is the shape the third test here pins down.
#[test]
fn the_summary_sentence_is_found_wherever_wrapping_put_it() {
    let wrapped = "Refuse a stream link\n\n\
         and the endpoint is refused. Three tests, mutation-proven both ways:\n\
         removing the rule fails two.\n";
    let (code, out) = claim(wrapped, "3");
    assert_eq!(code, 0, "a wrapped summary sentence was missed:\n{out}");

    let line_initial = "Watch the certificate\n\n\
         Seventeen tests, mutation-proven: dropping the guard fails one.\n";
    let (code, out) = claim(line_initial, "17");
    assert_eq!(code, 0, "a line-initial count was missed:\n{out}");
}

/// A count written outside the convention goes unchecked, deliberately.
///
/// The honest half of the trade. Narrowing to the summary sentence is what
/// keeps "8287 automated tests" and "these tests" from firing, and the cost is
/// that a count phrased some other way is not checked at all. NO CLAIM is its
/// own exit code rather than a pass wearing a disguise.
#[test]
fn a_count_written_outside_the_convention_is_not_a_claim() {
    for text in [
        "The commit adds four tests to the parser.",
        "Covered by 8287 automated tests.",
        "Two tests were removed and nothing replaced them yet, see below.",
    ] {
        let (code, out) = claim(text, "99");
        assert_eq!(code, 2, "{text:?} was read as a claim:\n{out}");
        assert!(out.contains("NO CLAIM"), "{out}");
    }
}

// ── Whether the origin certificate is load-bearing at all ───────────────────

/// Run the origin-certificate classifier over a verdict and a site status.
fn origin(cert_exit: &str, site_status: &str) -> (i32, String) {
    let out = Command::new("sh")
        .arg(repo().join("scripts/classify-origin-cert.sh"))
        .arg("--classify")
        .arg(cert_exit)
        .arg(site_status)
        .current_dir(repo())
        .output()
        .expect("the classifier runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

/// A healthy origin certificate is a pass, and says so plainly.
#[test]
fn a_healthy_origin_certificate_passes() {
    let (code, out) = origin("0", "200");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("OK"), "{out}");
}

/// A dead origin certificate behind a CDN that does not validate it is
/// TOLERATED — reported, and not a failure.
///
/// The distinction this file exists for, applied to itself. After the
/// 2026-09-11 outage the CDN was moved to a mode that terminates TLS at the
/// edge and reaches the origin over plain HTTP. The origin certificate then
/// decides nothing a visitor can see, so failing a daily job on it produces a
/// permanently red check, and a permanently red check is one nobody reads.
///
/// It is not silence either. The leg between the CDN and the origin is now
/// unencrypted and that is worth saying out loud, every day, in its own words.
#[test]
fn a_dead_origin_behind_a_tolerant_cdn_is_reported_not_failed() {
    let (code, out) = origin("2", "200");
    assert_eq!(
        code, 2,
        "a dead origin certificate that no visitor can be hurt by was scored \
         {code}:\n{out}"
    );
    assert!(out.contains("TOLERATED"), "{out}");
    assert!(
        out.to_lowercase().contains("unencrypted"),
        "the report does not say what is actually wrong — that the leg to the \
         origin carries no TLS:\n{out}"
    );
}

/// The same dead certificate with the site down is an outage, and fails.
///
/// This is the pairing that keeps the tolerance honest. The CDN mode is not
/// readable from here, so it is inferred from the only thing that matters:
/// whether anybody can load the page. Switch the CDN back to a validating mode
/// with a dead origin and the site answers 526, which lands here as a failure
/// on the very next run.
#[test]
fn a_dead_origin_with_a_dead_site_is_an_outage() {
    for status in ["526", "525", "000", "503"] {
        let (code, out) = origin("2", status);
        assert_eq!(
            code, 1,
            "status {status} with a dead origin was not scored as an \
             outage:\n{out}"
        );
        assert!(out.contains("OUTAGE"), "{status}:\n{out}");
    }
}

/// An origin inside the expiry margin is reported the same way.
///
/// EXPIRING and EXPIRED are different verdicts from the certificate checker
/// and both mean "renewal is not happening". Tolerating one and failing the
/// other would make the job flip red on a date rather than on a fact.
#[test]
fn an_expiring_origin_is_treated_like_an_expired_one() {
    let (expiring, out) = origin("1", "200");
    let (expired, _) = origin("2", "200");
    assert_eq!(expiring, expired, "{out}");
    assert_eq!(expiring, 2, "{out}");
}

/// Three situations, three exit codes.
#[test]
fn every_origin_verdict_has_its_own_exit_code() {
    let mut seen = std::collections::BTreeSet::new();
    for (cert, status, want) in [("0", "200", 0), ("2", "526", 1), ("2", "200", 2)] {
        let (code, out) = origin(cert, status);
        assert_eq!(code, want, "cert={cert} status={status}:\n{out}");
        assert!(seen.insert(code), "exit code {code} is used twice");
    }
    assert_eq!(seen.len(), 3, "{seen:?}");
}

/// The watcher runs the origin through the classifier rather than failing raw.
#[test]
fn the_watcher_judges_the_origin_rather_than_failing_on_it() {
    let wf = watcher();
    assert!(
        wf.contains("classify-origin-cert.sh"),
        "the origin step still fails on the certificate alone, which is red \
         every day while the CDN terminates TLS at the edge"
    );
    assert!(
        wf.contains("::warning::"),
        "a tolerated origin produces no annotation, so the unencrypted leg to \
         the origin is invisible rather than merely non-fatal"
    );
}

/// A CDN that refuses the checker has not told us the site is down.
///
/// Found on the first real run: from a GitHub runner the edge answered 403,
/// bot protection rather than a broken origin, and the classifier scored it as
/// the outage. It is the same mistake as the bare grep — one answer standing
/// for several situations — made by the thing built to stop making it.
///
/// A refusal says the edge is healthy and declined to talk to US. Nothing
/// about the origin follows from it, in either direction, so it is neither a
/// pass nor a failure.
#[test]
fn a_cdn_that_refuses_the_checker_is_not_an_outage() {
    for status in ["403", "429"] {
        let (code, out) = origin("2", status);
        assert_eq!(
            code, 3,
            "{status} from the edge was read as the site being down:\n{out}"
        );
        assert!(out.contains("BLOCKED"), "{status}:\n{out}");
        assert!(
            !out.contains("OUTAGE"),
            "a refused checker is being reported as an outage:\n{out}"
        );
    }
}

/// A refusal is not silently a pass either.
///
/// The other half, and the one that matters more: if BLOCKED were folded into
/// OK, the watcher would go quiet the moment the CDN started refusing it, which
/// is exactly when it has stopped watching anything at all.
#[test]
fn a_refused_checker_is_never_scored_as_healthy() {
    let (blocked, out) = origin("2", "403");
    let (ok, _) = origin("0", "200");
    assert_ne!(
        blocked, ok,
        "a checker that was refused reports the same verdict as a healthy \
         origin, so the watcher goes quiet exactly when it stops working:\n{out}"
    );
}

/// Four situations, four exit codes.
#[test]
fn a_blocked_check_has_its_own_exit_code() {
    let mut seen = std::collections::BTreeSet::new();
    for (cert, status, want) in [
        ("0", "200", 0),
        ("2", "526", 1),
        ("2", "200", 2),
        ("2", "403", 3),
    ] {
        let (code, out) = origin(cert, status);
        assert_eq!(code, want, "cert={cert} status={status}:\n{out}");
        assert!(seen.insert(code), "exit code {code} is used twice");
    }
    assert_eq!(seen.len(), 4, "{seen:?}");
}

/// The watcher identifies itself rather than arriving as an anonymous bot.
///
/// The 403 came from bot protection, and the first thing to try is simply not
/// looking like a scraper. A named agent also tells whoever reads the CDN logs
/// who this is.
#[test]
fn the_watcher_identifies_itself_to_the_cdn() {
    let wf = watcher();
    assert!(
        wf.contains("--user-agent") || wf.contains("-A "),
        "the site check sends no user agent, so the CDN sees an anonymous \
         client and may refuse it — which is how the first run scored a 403 \
         as the site being down"
    );
}
