// SPDX-License-Identifier: MIT OR Apache-2.0

//! The harness can swap its media anchor, and the swap is total.
//!
//! Given/When/Then over the compose file and the OpenSIPS entrypoint, because
//! the anchor is a property of the STACK rather than of any one container. A
//! swap that left half the old anchor running would produce a capture nobody
//! could interpret: two relays, one call, and no way to say which anchored it.
//!
//! These read configuration rather than a running stack on purpose. A test
//! that needs docker cannot run in CI, and the coupling worth holding is that
//! the files agree with each other.

#![cfg(feature = "full")]

use std::path::PathBuf;

fn harness(file: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("harness")
        .join(file);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn compose() -> String {
    harness("docker-compose.yml")
}

fn entrypoint() -> String {
    harness("opensips/entrypoint.sh")
}

// ── The anchor is a choice, and every value is real ──────────────────────────

/// GIVEN the OpenSIPS entrypoint
/// WHEN an anchor is selected
/// THEN all three values load a different relay module, or none at all.
#[test]
fn every_anchor_value_selects_a_real_configuration() {
    let e = entrypoint();
    assert!(e.contains(r#"loadmodule "rtpengine.so""#));
    assert!(e.contains(r#"loadmodule "rtpproxy.so""#));
    assert!(
        e.contains("MEDIA_ANCHOR=none: no relay module loaded"),
        "`none` must be a first-class value: it is the control the anchored \
         runs are measured against"
    );
}

/// GIVEN an unknown anchor name
/// WHEN the entrypoint runs
/// THEN it refuses loudly rather than defaulting to one silently.
#[test]
fn an_unknown_anchor_is_refused_not_defaulted() {
    let e = entrypoint();
    assert!(
        e.contains("FATAL: MEDIA_ANCHOR=") && e.contains("exit 1"),
        "a typo in the anchor name must not quietly run rtpengine"
    );
}

/// GIVEN each anchor
/// WHEN a call is offered
/// THEN the offer, answer and teardown all come from the SAME module family.
///
/// A half-swapped script -- rtpproxy offering and rtpengine deleting -- leaves
/// sessions on one relay forever, and the capture shows a call that never
/// tears down.
#[test]
fn an_anchor_offers_answers_and_tears_down_with_one_module() {
    let e = entrypoint();
    for verb in ["offer", "answer"] {
        assert!(
            e.contains(&format!("rtpengine_{verb}()")),
            "rtpengine is missing {verb}"
        );
        assert!(
            e.contains(&format!("rtpproxy_{verb}()")),
            "rtpproxy is missing {verb}"
        );
    }
    assert!(e.contains("rtpengine_delete()"), "rtpengine teardown");
    assert!(
        e.contains("rtpproxy_unforce()"),
        "rtpproxy tears down with unforce, not delete -- a different module's \
         spelling would not compile in the script"
    );
}

/// GIVEN the `none` anchor
/// WHEN a reply carrying SDP arrives
/// THEN the script still has a statement, because an empty route is rejected.
#[test]
fn the_control_anchor_still_produces_a_valid_script() {
    let e = entrypoint();
    assert!(
        e.contains("return;   # MEDIA_ANCHOR=none"),
        "OpenSIPS rejects an EMPTY onreply_route; the control run needs a real \
         statement rather than a comment"
    );
}

// ── One anchor at a time ─────────────────────────────────────────────────────

/// GIVEN the compose file
/// WHEN both relays are defined
/// THEN each sits behind its own profile, so only one runs.
#[test]
fn each_anchor_sits_behind_its_own_profile() {
    let c = compose();
    assert!(c.contains(r#"profiles: ["rtpengine"]"#));
    assert!(c.contains(r#"profiles: ["rtpproxy"]"#));
}

/// GIVEN a stack already running one anchor
/// WHEN another is selected
/// THEN the Makefile removes the previous anchor's containers.
#[test]
fn selecting_an_anchor_removes_the_other_ones_containers() {
    let m = harness("Makefile");
    assert!(
        m.contains("stop-other-anchors"),
        "without this the old relay keeps running and the capture has two"
    );
    assert!(m.contains("sipnab-relay-rtpproxy") && m.contains("rtpproxy"));
}

/// GIVEN each anchor profile
/// WHEN it runs
/// THEN it publishes the SAME host ports, so a swap is not a new set of doors.
#[test]
fn both_anchors_publish_the_same_host_ports() {
    let c = compose();
    let relay_mcp = c.matches("RELAY_MCP_PORT:-8732").count();
    let relay_api = c.matches("RELAY_API_PORT:-8081").count();
    assert!(
        relay_mcp >= 2 && relay_api >= 2,
        "each anchor must publish the same relay doors ({relay_mcp} MCP, \
         {relay_api} REST); a swap that moved them makes every saved client \
         config wrong"
    );
}

// ── sipnab watches the control plane of whichever anchor runs ────────────────

/// GIVEN the rtpproxy profile
/// WHEN sipnab captures beside it
/// THEN its capture filter includes rtpproxy's control port.
///
/// This was written into the harness BEFORE a decoder existed, so the evidence
/// would be in the pcap when one arrived. It has arrived.
#[test]
fn sipnab_captures_the_rtpproxy_control_port() {
    let c = compose();
    assert!(
        c.contains(r#"CONTROL_PORTS: "22223""#),
        "the rtpproxy relay instance must watch the control socket, or the \
         command exchange is not in the capture at all"
    );
}

/// GIVEN the rtpproxy container
/// WHEN OpenSIPS is configured to reach it
/// THEN both name the SAME control socket.
#[test]
fn opensips_and_rtpproxy_agree_on_the_control_socket() {
    let c = compose();
    assert!(
        c.contains("RTPPROXY_CTL_BIND: ${RTPPROXY_IP:-172.28.0.12}:22223"),
        "the relay binds its control socket here"
    );
    assert!(
        c.contains("22223"),
        "and OpenSIPS must be pointed at the same one"
    );
}

/// GIVEN rtpproxy anchoring media
/// WHEN sipnab runs beside it
/// THEN it does not expect HEP, because rtpproxy mirrors nothing.
#[test]
fn the_rtpproxy_instance_does_not_expect_hep() {
    let c = compose();
    // Read the service block by INDENTATION, not by a character count. A fixed
    // window expires the moment the block grows, and it would have been read
    // as a pass here rather than as a stale test.
    let mut in_block = false;
    let mut keys = Vec::new();
    for line in c.lines() {
        if line.trim_start().starts_with("sipnab-relay-rtpproxy:") {
            in_block = true;
            continue;
        }
        if in_block {
            let indent = line.len() - line.trim_start().len();
            if !line.trim().is_empty() && indent <= 2 {
                break;
            }
            // The SETTING, not the prose. The block carries a comment saying
            // why HEP is absent, and matching that would pass for the wrong
            // reason -- a test satisfied by an explanation rather than by the
            // configuration it explains.
            if let Some((key, _)) = line.trim().split_once(':')
                && !line.trim_start().starts_with('#')
            {
                keys.push(key.trim().to_string());
            }
        }
    }
    assert!(in_block, "the rtpproxy relay instance is defined");
    assert!(
        !keys.iter().any(|k| k == "HEP_PARSE"),
        "rtpproxy has no HEP mirror; asking for one would make every run \
         report a mirror that was never configured. Keys: {keys:?}"
    );
    assert!(
        keys.iter().any(|k| k == "CONTROL_PORTS"),
        "and the block must really have been read, or this proves nothing: \
         {keys:?}"
    );
}

// ── The two anchors never contend for a port ─────────────────────────────────

/// GIVEN both anchors defined in one stack
/// WHEN their media ranges are compared
/// THEN the ranges are disjoint.
///
/// They could have shared one: the profiles are mutually exclusive, so only a
/// Makefile target stops both running. "Safe because nobody can run both" is a
/// rule enforced somewhere other than the numbers, and a capture holding two
/// anchors on one port pair is one nobody can interpret.
#[test]
fn the_two_anchors_media_ranges_do_not_overlap() {
    let env = harness(".env");
    let value = |key: &str| -> u16 {
        env.lines()
            .find_map(|l| l.trim().strip_prefix(&format!("{key}=")))
            .and_then(|v| v.split_whitespace().next())
            .unwrap_or_else(|| panic!("{key} is not set"))
            .parse()
            .unwrap_or_else(|e| panic!("{key}: {e}"))
    };
    let (engine_lo, engine_hi) = (value("RTP_MIN"), value("RTP_MAX"));
    let (proxy_lo, proxy_hi) = (value("RTPPROXY_RTP_MIN"), value("RTPPROXY_RTP_MAX"));

    assert!(engine_lo <= engine_hi, "rtpengine range is inverted");
    assert!(proxy_lo <= proxy_hi, "rtpproxy range is inverted");
    assert!(
        engine_hi < proxy_lo || proxy_hi < engine_lo,
        "the ranges overlap: rtpengine {engine_lo}-{engine_hi} and rtpproxy \
         {proxy_lo}-{proxy_hi}. A call anchored by one would land on ports the \
         other claims."
    );
}

/// GIVEN the two ranges
/// WHEN the gap between them is measured
/// THEN it is wide enough that an accidental overlap is obvious.
///
/// Adjacent ranges are disjoint and still a trap: moving either boundary by
/// one collides, and a one-port collision shows up as a single one-way call
/// nobody connects to a configuration change.
#[test]
fn the_gap_between_the_ranges_is_visible_not_incidental() {
    let env = harness(".env");
    let value = |key: &str| -> u16 {
        env.lines()
            .find_map(|l| l.trim().strip_prefix(&format!("{key}=")))
            .and_then(|v| v.split_whitespace().next())
            .unwrap_or_else(|| panic!("{key} is not set"))
            .parse()
            .expect("a port")
    };
    let engine_hi = value("RTP_MAX");
    let proxy_lo = value("RTPPROXY_RTP_MIN");
    let gap = proxy_lo.saturating_sub(engine_hi);
    assert!(
        gap >= 100,
        "only {gap} port(s) between the ranges; a boundary edited by hand \
         should not be able to collide without somebody noticing"
    );
}

/// GIVEN the rtpproxy container
/// WHEN it publishes media ports
/// THEN it publishes its OWN range and not the other anchor's.
#[test]
fn each_anchor_publishes_the_range_it_actually_uses() {
    let c = compose();
    assert!(
        c.contains("${RTPPROXY_RTP_MIN:-31000}-${RTPPROXY_RTP_MAX:-31050}:31000-31050/udp"),
        "rtpproxy must publish its own range, or the container allocates ports \
         nothing forwards and every call is one-way"
    );
    assert!(
        c.contains("${RTP_MIN:-30000}-${RTP_MAX:-30050}:30000-30050/udp"),
        "and rtpengine must keep publishing its own"
    );
}

/// GIVEN the rtpproxy container
/// WHEN it is told which ports to allocate from
/// THEN it is told its own range, not the shared default.
#[test]
fn the_relay_is_told_the_same_range_that_is_published() {
    let c = compose();
    let mut in_block = false;
    let mut min = None;
    let mut max = None;
    for line in c.lines() {
        if line.trim_start().starts_with("rtpproxy:") {
            in_block = true;
            continue;
        }
        if in_block {
            let indent = line.len() - line.trim_start().len();
            if !line.trim().is_empty() && indent <= 2 {
                break;
            }
            if let Some(v) = line.trim().strip_prefix("RTP_MIN:") {
                min = Some(v.trim().to_string());
            }
            if let Some(v) = line.trim().strip_prefix("RTP_MAX:") {
                max = Some(v.trim().to_string());
            }
        }
    }
    assert_eq!(
        min.as_deref(),
        Some("${RTPPROXY_RTP_MIN:-31000}"),
        "the relay allocates from the range it was told, and publishing one \
         while allocating from another is a silent one-way call"
    );
    assert_eq!(max.as_deref(), Some("${RTPPROXY_RTP_MAX:-31050}"));
}
