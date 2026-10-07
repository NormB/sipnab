// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(unix, feature = "hep"))]
//! `--hep-parse` (`-E`, `[capture] hep_parse`) on every path that reads
//! packets, not only the headless one.
//!
//! Until this, only the single-threaded headless loop unwrapped HEP. The TUI
//! (a user sniffing an OpenSIPS HEP copy on `lo` saw 0 dialogs where `-N` saw
//! 155 messages) and `--cores N` read the HEP datagram as an ordinary UDP
//! payload and found no SIP in it. Each test here drives one path with the
//! same HEP-wrapped call and asserts the call comes out; each has a negative
//! control without `--hep-parse`, which must find nothing, or the test would
//! pass for a path that never needed unwrapping.

#[path = "support/pcap_build.rs"]
mod pcap_build;

/// The TUI's processing thread: `TuiPacketThread::process` with the options the
/// thread builds from the command line and the config file.
#[cfg(all(feature = "tui", feature = "tls"))]
mod tui_thread {
    use std::sync::Arc;

    use clap::Parser;
    use parking_lot::RwLock;
    use sipnab::app::tui_mode::{TuiMedia, TuiOutput, TuiPacketThread, tui_pipeline_options};
    use sipnab::capture::{Packet, PacketProcessor, ParsedPacket};
    use sipnab::cli::Cli;
    use sipnab::config::Config;
    use sipnab::rtp::heuristic::RtpHeuristic;
    use sipnab::rtp::stream_store::StreamStore;
    use sipnab::sip::dialog_store::DialogStore;

    /// Feed the HEP-wrapped call through the TUI thread's per-packet work.
    ///
    /// # Returns
    ///
    /// `(dialogs, packets the live detectors observed as SIP)`.
    fn run(args: &[&str], config: &Config) -> (usize, usize) {
        let frames = super::pcap_build::hep_call_frames("tui-hep@example.com");
        let (dialogs, observed_sip, _) = run_frames(args, config, &frames);
        (dialogs, observed_sip)
    }

    /// [`run`] over any frames.
    ///
    /// # Returns
    ///
    /// `(dialogs, packets observed as the call's SIP, packets observed at
    /// all)`.
    fn run_frames(args: &[&str], config: &Config, frames: &[Vec<u8>]) -> (usize, usize, usize) {
        let cli = Cli::parse_from(args);
        let mut thread = TuiPacketThread {
            output: TuiOutput::new(&cli, (None, None, None)),
            processor: PacketProcessor::new(),
            rtp_heuristic: RtpHeuristic::new(),
            media: TuiMedia::from_cli(&cli),
            opts: tui_pipeline_options(&cli, config, false),
            relay_orphans: None,
            dialogs: Arc::new(RwLock::new(DialogStore::new(64, false))),
            streams: Arc::new(RwLock::new(StreamStore::new(64))),
        };
        let mut observed_sip = 0usize;
        let mut observed_any = 0usize;
        let base = chrono::Utc::now();
        for (i, f) in frames.iter().enumerate() {
            let p = Packet {
                timestamp: base + chrono::Duration::milliseconds(i as i64),
                data: f.clone().into(),
                caplen: f.len(),
                origlen: f.len(),
                interface: None,
                link_type: 1,
                pre_parsed: None,
                origin: None,
            };
            thread
                .process(&p, false, |pp: &ParsedPacket| {
                    observed_any += 1;
                    // The call's own SIP, not the HEP datagram that
                    // carried it: the Call-ID line is in all seven messages,
                    // and a wrapper's payload starts `HEP3`.
                    let text = String::from_utf8_lossy(&pp.payload);
                    if !pp.payload.starts_with(b"HEP3")
                        && text.contains("Call-ID: tui-hep@example.com")
                    {
                        observed_sip += 1;
                    }
                })
                .expect("process");
        }
        let dialogs = thread.dialogs.read().len();
        (dialogs, observed_sip, observed_any)
    }

    /// A HEP datagram whose IP protocol chunk names no transport (99) is
    /// counted NOT DECODED and goes no further: no dialog, and the live
    /// detectors are not handed the wrapper as if it were a UDP packet.
    #[test]
    #[serial_test::serial(undecodable_tally)]
    fn the_tui_thread_drops_hep_whose_transport_no_rule_names() {
        sipnab::capture::reset_undecodable_frames();
        let frame = super::pcap_build::hep_frame_with_ip_proto_or_panic(99);
        let (dialogs, _, observed) = run_frames(
            &["sipnab", "-d", "lo", "-E"],
            &Config::default(),
            std::slice::from_ref(&frame),
        );
        assert_eq!(dialogs, 0);
        assert_eq!(observed, 0, "the detectors never see the datagram");
        assert_eq!(
            sipnab::capture::undecodable_frames(),
            1,
            "counted NOT DECODED"
        );
        // The control: without -E the datagram is ordinary UDP, handed on as
        // such and not counted.
        sipnab::capture::reset_undecodable_frames();
        let (_, _, observed) = run_frames(&["sipnab", "-d", "lo"], &Config::default(), &[frame]);
        assert_eq!(
            observed, 1,
            "without -E the UDP datagram reaches the detectors"
        );
        assert_eq!(sipnab::capture::undecodable_frames(), 0);
    }

    /// `-E` on the TUI's command line unwraps the HEP copy: the call is one
    /// dialog, and the live detectors see the SIP inside, not the wrapper.
    #[test]
    fn the_tui_thread_unwraps_hep_with_the_flag() {
        let (dialogs, observed) = run(&["sipnab", "-d", "lo", "-E"], &Config::default());
        assert_eq!(dialogs, 1, "the HEP-wrapped call is one dialog");
        assert_eq!(observed, 7, "the detectors see all 7 SIP messages");
    }

    /// `[capture] hep_parse = true` does the same with no flag.
    #[test]
    fn the_tui_thread_unwraps_hep_with_the_config_key() {
        let mut config = Config::default();
        config.capture.hep_parse = Some(true);
        let (dialogs, _) = run(&["sipnab", "-d", "lo"], &config);
        assert_eq!(dialogs, 1, "[capture] hep_parse reaches the TUI");
    }

    /// The negative control: without `--hep-parse` the same frames hold no
    /// SIP the TUI can see.
    #[test]
    fn without_hep_parse_the_tui_thread_sees_no_call() {
        let (dialogs, observed) = run(&["sipnab", "-d", "lo"], &Config::default());
        assert_eq!(dialogs, 0);
        assert_eq!(observed, 0);
    }
}

/// `--cores N` on a capture file of HEP-wrapped SIP.
mod cores {
    use std::process::Command;

    /// `sipnab -N -I <hep.pcap> --json-dialogs --no-config` plus `extra`;
    /// returns stdout.
    fn run(extra: &[&str]) -> String {
        let dir = tempfile::tempdir().expect("tempdir");
        let pcap = dir.path().join("hep.pcap");
        super::pcap_build::write_pcap_or_panic(
            &pcap,
            &super::pcap_build::hep_call_frames("cores-hep@example.com"),
        );
        let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args([
                "-N",
                "-I",
                pcap.to_str().expect("utf-8"),
                "--json-dialogs",
                "--no-config",
                "--quiet",
            ])
            .args(extra)
            .env("SIPNAB_LOG", "error")
            .env("NO_COLOR", "1")
            .output()
            .expect("run sipnab");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Under `--cores`, a HEP datagram whose transport no rule names is
    /// reported NOT DECODED, as the single-threaded run reports it, and the
    /// readable call beside it still comes out.
    #[test]
    fn cores_reports_undecodable_hep() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pcap = dir.path().join("hep.pcap");
        let mut frames = vec![super::pcap_build::hep_frame_with_ip_proto_or_panic(99)];
        frames.extend(super::pcap_build::hep_call_frames("cores-hep@example.com"));
        super::pcap_build::write_pcap_or_panic(&pcap, &frames);
        for cores in ["1", "2"] {
            let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
                .args([
                    "-N",
                    "-I",
                    pcap.to_str().expect("utf-8"),
                    "--json-dialogs",
                    "--no-config",
                    "-E",
                    "--cores",
                    cores,
                ])
                .env("NO_COLOR", "1")
                .output()
                .expect("run sipnab");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stdout.contains("cores-hep@example.com"),
                "--cores {cores}: the call:\n{stdout}"
            );
            assert!(
                stderr.contains("NOT DECODED") && stderr.contains("99"),
                "--cores {cores}: the protocol-99 datagram is reported:\n{stderr}"
            );
        }
    }

    /// `--cores 2 -E` reports the call `--cores 1 -E` reports. The control
    /// is `--cores 2` without `-E`, which must report none.
    #[test]
    fn cores_unwraps_hep_like_the_single_threaded_path() {
        let single = run(&["-E"]);
        assert!(
            single.contains("cores-hep@example.com"),
            "the single-threaded path reports the call:\n{single}"
        );
        let parallel = run(&["-E", "--cores", "2"]);
        assert!(
            parallel.contains("cores-hep@example.com"),
            "--cores 2 -E must report the call too:\n{parallel}"
        );
        let unwrapped_nowhere = run(&["--cores", "2"]);
        assert!(
            !unwrapped_nowhere.contains("cores-hep@example.com"),
            "without -E the HEP datagrams hold no SIP:\n{unwrapped_nowhere}"
        );
    }
}

/// A capture opened from inside the TUI (the file browser, and the BPF
/// editor's re-scan), with the options the session starts with.
#[cfg(feature = "tui")]
mod tui_file_open {
    use crossterm::event::KeyCode;

    /// Open the HEP-wrapped call from the TUI's file browser with
    /// `hep_parse` set as `src/app` sets it, and return the dialog count once
    /// the background load finishes.
    fn open(hep_parse: bool) -> usize {
        let dir = tempfile::tempdir().expect("tempdir");
        super::pcap_build::write_pcap_or_panic(
            &dir.path().join("hep.pcap"),
            &super::pcap_build::hep_call_frames("open-hep@example.com"),
        );
        open_dir(dir.path(), hep_parse)
    }

    /// Open `dir/hep.pcap` from the file browser; the dialog count once the
    /// load settles.
    fn open_dir(dir: &std::path::Path, hep_parse: bool) -> usize {
        let options = sipnab::tui::TuiOptions {
            capture_options: sipnab::pipeline::PipelineOptions {
                hep_parse,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut app = options.into_app(
            std::sync::Arc::new(parking_lot::RwLock::new(
                sipnab::sip::dialog_store::DialogStore::new(100, false),
            )),
            std::sync::Arc::new(parking_lot::RwLock::new(
                sipnab::rtp::stream_store::StreamStore::new(100),
            )),
        );
        app.set_open_dir_for_test(dir.to_path_buf());
        app.handle_key(KeyCode::Char('O'));
        assert_eq!(
            app.open_entry_names_for_test(),
            vec!["..".to_string(), "hep.pcap".to_string()]
        );
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Enter);
        // The load runs on a worker thread; a seven-frame file finishes in
        // milliseconds, and the deadline only bounds a hang.
        let by = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let n = app.dialog_store_ref().read().len();
            if n > 0 || std::time::Instant::now() >= by {
                return n;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn a_capture_opened_in_the_tui_unwraps_hep() {
        assert_eq!(open(true), 1, "the opened HEP copy is one dialog");
    }

    /// A HEP datagram whose transport no rule names is counted NOT DECODED
    /// when a capture is opened in the TUI, as in a headless run, and adds no
    /// dialog. The background load is waited out through the counter.
    #[test]
    #[serial_test::serial(undecodable_tally)]
    fn a_capture_opened_in_the_tui_counts_undecodable_hep() {
        sipnab::capture::reset_undecodable_frames();
        let dir = tempfile::tempdir().expect("tempdir");
        let mut frames = vec![super::pcap_build::hep_frame_with_ip_proto_or_panic(99)];
        frames.extend(super::pcap_build::hep_call_frames("open-hep@example.com"));
        super::pcap_build::write_pcap_or_panic(&dir.path().join("hep.pcap"), &frames);
        let dialogs = open_dir(dir.path(), true);
        assert_eq!(dialogs, 1, "the readable call still loads");
        assert_eq!(
            sipnab::capture::undecodable_frames(),
            1,
            "the protocol-99 datagram is NOT DECODED"
        );
    }

    /// The negative control. It waits out the deadline, because "nothing
    /// yet" and "nothing ever" look alike until then.
    #[test]
    fn without_hep_parse_the_opened_capture_holds_no_call() {
        assert_eq!(open(false), 0);
    }
}
