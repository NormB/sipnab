// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A Call-ID that spans the files of an `-I` set on different host pairs
//! reconstructs the same at every `--cores`.
//!
//! `--cores N` shards packets by host pair, so the fragments of such a
//! Call-ID land on different workers, and the merge at the end of the run
//! joins them. `--cores 1` defines the answer: it feeds every message to one
//! dialog store in the order the set is read, file by file in the order of
//! each file's first packet. When the files overlap in time that order is not
//! timestamp order, and a merge that ordered a call's fragments by timestamp
//! (as it did through 0.5.236) reported other durations, timings and SDP
//! timelines than `--cores 1`, depending on which worker owned which pair.
//!
//! The fixture is `synthetic_captures::callid_across_files`: sixteen
//! Call-IDs, each on three host pairs across two overlapping captures.

#[path = "support/synthetic_captures.rs"]
mod synthetic_captures;

#[path = "support/codecs.rs"]
mod codecs;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The worker counts compared against `--cores 1`.
const CORE_COUNTS: [&str; 3] = ["2", "3", "4"];

/// The two captures, written to `dir`, edge first.
fn write_set(dir: &std::path::Path) -> Result<[std::path::PathBuf; 2], TestError> {
    let [edge, core] = synthetic_captures::callid_across_files();
    let paths = [dir.join("edge.pcap"), dir.join("core.pcap")];
    std::fs::write(&paths[0], edge)?;
    std::fs::write(&paths[1], core)?;
    Ok(paths)
}

/// Standard output of `sipnab -N` over the set at `cores`, with `args`.
///
/// The core capture is named first on purpose: the set is read in the order
/// of each file's first packet, not the order of the arguments.
fn run(set: &[std::path::PathBuf; 2], cores: &str, args: &[&str]) -> Result<String, TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("-N")
        .arg("-I")
        .arg(&set[1])
        .arg("-I")
        .arg(&set[0])
        .args(["--cores", cores])
        .args(args)
        .output()?;
    assert!(
        out.status.success(),
        "--cores {cores} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?)
}

/// The report from the dialog table's header on.
fn report(set: &[std::path::PathBuf; 2], cores: &str) -> Result<String, TestError> {
    let stdout = run(set, cores, &["--report"])?;
    let start = stdout
        .find("Call-ID ")
        .ok_or_else(|| format!("--cores {cores} printed no dialog table:\n{stdout}"))?;
    Ok(stdout[start..].to_string())
}

/// The fixture splits Call-IDs across workers at every compared core count,
/// so each comparison below exercises the merge rather than a run in which
/// every Call-ID happened to stay on one worker.
#[cfg(feature = "native")]
#[test]
fn the_fixture_splits_a_call_id_across_workers_at_every_core_count() -> Result<(), TestError> {
    for cores in CORE_COUNTS {
        let n: usize = cores.parse()?;
        let split = (0..synthetic_captures::SPANNING_CALLS).any(|i| {
            let shards: std::collections::BTreeSet<usize> = synthetic_captures::spanning_pairs(i)
                .into_iter()
                .map(|(a, b)| {
                    sipnab::parallel::shard_for(
                        std::net::IpAddr::from(a),
                        std::net::IpAddr::from(b),
                        n,
                    )
                })
                .collect();
            shards.len() > 1
        });
        assert!(
            split,
            "no Call-ID of the fixture spans two workers at --cores {n}"
        );
    }
    Ok(())
}

#[test]
fn the_report_is_the_same_at_every_core_count() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let set = write_set(dir.path())?;
    let single = report(&set, "1")?;
    for i in 0..synthetic_captures::SPANNING_CALLS {
        assert!(
            single.contains(&format!("span-{i}@example.com")),
            "--cores 1 is missing span-{i}:\n{single}"
        );
    }
    for cores in CORE_COUNTS {
        assert_eq!(
            report(&set, cores)?,
            single,
            "--cores {cores} reports differently from --cores 1"
        );
    }
    Ok(())
}

#[test]
fn json_dialogs_are_the_same_at_every_core_count() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let set = write_set(dir.path())?;
    let args = ["--json-dialogs", "--no-cli-print"];
    let single = run(&set, "1", &args)?;
    assert_eq!(
        single.lines().count(),
        usize::from(synthetic_captures::SPANNING_CALLS),
        "one dialog per Call-ID at --cores 1:\n{single}"
    );
    for cores in CORE_COUNTS {
        let multi = run(&set, cores, &args)?;
        for (one, many) in single.lines().zip(multi.lines()) {
            assert_eq!(many, one, "--cores {cores} differs from --cores 1");
        }
        assert_eq!(multi, single, "--cores {cores} differs from --cores 1");
    }
    Ok(())
}

#[test]
fn json_analyze_is_the_same_at_every_core_count() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let set = write_set(dir.path())?;
    let args = ["--json-analyze", "--no-cli-print"];
    let single = run(&set, "1", &args)?;
    assert!(
        single.trim_start().starts_with('{'),
        "--json-analyze printed no object:\n{single}"
    );
    for cores in CORE_COUNTS {
        assert_eq!(
            run(&set, cores, &args)?,
            single,
            "--cores {cores} analyzes differently from --cores 1"
        );
    }
    Ok(())
}

/// A vCon container with the two fields that differ between ANY two runs
/// removed: its own `created_at`, the time the container was written, and the
/// `uuid` of each object inside it, which is random.
#[cfg(feature = "vcon")]
fn comparable(mut v: serde_json::Value) -> serde_json::Value {
    fn strip_uuids(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                map.remove("uuid");
                map.values_mut().for_each(strip_uuids);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(strip_uuids),
            _ => {}
        }
    }
    if let Some(map) = v.as_object_mut() {
        map.remove("created_at");
        map.values_mut().for_each(strip_uuids);
    }
    v
}

/// Every container `--export-vcon-when` writes at `cores`, by file name.
#[cfg(feature = "vcon")]
fn vcons(
    set: &[std::path::PathBuf; 2],
    cores: &str,
    out: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, serde_json::Value>, TestError> {
    std::fs::create_dir(out)?;
    let dir = out.to_str().ok_or("a UTF-8 temp path")?;
    run(
        set,
        cores,
        &[
            "--export-vcon-when",
            "method == INVITE",
            "--export-vcon-dir",
            dir,
            "--no-cli-print",
        ],
    )?;
    let mut by_name = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(out)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| format!("{n:?}"))?;
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(entry.path())?)?;
        by_name.insert(name, comparable(v));
    }
    Ok(by_name)
}

#[cfg(feature = "vcon")]
#[test]
fn the_vcon_set_is_the_same_at_every_core_count() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let set = write_set(dir.path())?;
    let single = vcons(&set, "1", &dir.path().join("vcon-1"))?;
    assert_eq!(
        single.len(),
        usize::from(synthetic_captures::SPANNING_CALLS),
        "one container per Call-ID at --cores 1: {:?}",
        single.keys().collect::<Vec<_>>()
    );
    for cores in CORE_COUNTS {
        let multi = vcons(&set, cores, &dir.path().join(format!("vcon-{cores}")))?;
        assert_eq!(
            multi.keys().collect::<Vec<_>>(),
            single.keys().collect::<Vec<_>>(),
            "--cores {cores} writes other containers than --cores 1"
        );
        for (name, one) in &single {
            assert_eq!(
                multi.get(name),
                Some(one),
                "--cores {cores} writes {name} differently from --cores 1"
            );
        }
    }
    Ok(())
}

/// What a run reconstructed, as the dialog and stream summaries the reports
/// are built from, in the order the stores list them.
#[cfg(feature = "native")]
fn reconstruction(r: &sipnab::parallel::ReconResult) -> Result<Vec<String>, TestError> {
    let mut rows = Vec::new();
    for d in r.dialog_store.iter() {
        rows.push(serde_json::to_string(
            &sipnab::output::model::DialogSummary::from(d),
        )?);
    }
    for s in r.stream_store.iter() {
        rows.push(format!(
            "{:?}",
            (
                &s.key,
                s.first_frame.as_ref().map(|f| f.origin.ordinal),
                &s.associated_dialog,
                (s.first_seen, s.last_seen, s.packet_count, s.lost_packets),
            )
        ));
    }
    Ok(rows)
}

/// The `--cores` path over the set at `cores` workers, grouping host pairs
/// by `assignment` (see `ParallelConfig::shard_assignment`).
#[cfg(feature = "native")]
fn sharded(
    set: &[std::path::PathBuf; 2],
    cores: usize,
    assignment: u64,
) -> Result<sipnab::parallel::ReconResult, TestError> {
    let cfg = sipnab::parallel::ParallelConfig {
        cores,
        max_streams: 100_000,
        max_dialogs: 100_000,
        rotate: false,
        max_reassembly: 1024,
        reassembly: true,
        parse_limit: None,
        shard_assignment: assignment,
        portrange: (5060, 5060),
        no_dialog: false,
        dialog_tracking: Default::default(),
        no_rtp: false,
        quiet_bad_parse: false,
        hep_parse: false,
        rtpproxy_control: None,
        ng_control_port: None,
        xcid_headers: Vec::new(),
        leg_correlation_window_ms: sipnab::sip::dialog_store::DEFAULT_LEG_CORRELATION_WINDOW_MS,
        retain_audio: false,
        audio_limits: sipnab::rtp::stream_store::AudioLimits::default(),
    };
    let cc = sipnab::capture::CaptureConfig::default();
    Ok(sipnab::parallel::run_offline_parallel_file(
        &[set[0].clone(), set[1].clone()],
        &cc,
        cfg,
    )?)
}

/// The reconstruction does not depend on which host pairs share a worker.
///
/// Each number is a different assignment of the fixture's 48 host pairs to
/// workers. A merge whose result depends on that assignment (as the
/// timestamp-ordered dialog merge did) gives a different answer for some of
/// them; a later change to the shard hash is one more assignment, so this is
/// what lets it land without changing a report.
#[cfg(feature = "native")]
#[test]
fn the_reconstruction_does_not_depend_on_the_shard_assignment() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let set = write_set(dir.path())?;
    let reference = reconstruction(&sharded(&set, 2, 0)?)?;
    assert!(
        reference.len() > usize::from(synthetic_captures::SPANNING_CALLS),
        "the set reconstructed dialogs and streams: {reference:?}"
    );
    for cores in 2..=4 {
        for assignment in 0..12 {
            let got = reconstruction(&sharded(&set, cores, assignment)?)?;
            for (one, other) in reference.iter().zip(&got) {
                assert_eq!(other, one, "--cores {cores}, assignment {assignment}");
            }
            assert_eq!(
                got.len(),
                reference.len(),
                "--cores {cores}, assignment {assignment}"
            );
        }
    }
    Ok(())
}
