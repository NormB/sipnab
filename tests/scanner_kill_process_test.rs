// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scanner-kill worker is a process of its own, and the process parsing
//! captured traffic holds none of its send descriptors.
//!
//! `--kill-scanner` is the only part of sipnab that transmits. Its worker used
//! to be a thread in the same address space as libpcap, the parsers, TLS key
//! material and bearer tokens, holding the `CAP_NET_RAW` raw sockets for the
//! whole run. It is now this binary re-executed: the parent creates every
//! descriptor the worker sends through, hands them over at fixed numbers, and
//! closes its own copies. These tests drive that against the real binary.
//!
//! # What cannot be driven here, and why
//!
//! The raw-socket path needs `CAP_NET_RAW` to open a socket, and nothing in
//! this suite runs privileged. What reaches the worker is the conversion — the
//! descriptor plan, the fixed slots and the worker's argument parsing — and
//! that is pinned by the unit tests in `src/process_isolation/worker_process.rs`.
//! The ephemeral UDP path below goes through the same inheritance end to end.
//!
//! # Safety of the traffic
//!
//! Every kill response in this file is addressed to a UDP listener the test
//! itself binds on 127.0.0.1. Nothing is sent anywhere else.
#![cfg(all(target_os = "linux", feature = "native"))]

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crossbeam_channel::TrySendError;
use sipnab::process_isolation::worker_process::KILL_WORKER_ARG;
use sipnab::process_isolation::{
    KillRequest, KillResponse, KillWorkerSpawn, ScannerKillHandle, SendPath, kill_responses_sent,
    spawn_scanner_kill_worker, wire,
};
use sipnab::security::transmit_guard::TransmitPermit;

include!("support/timeout.rs");
include!("support/teardown.rs");

/// A permit for a live source: the worker exists only for one, and these
/// tests declare it exactly as a real run does.
fn live_permit() -> TransmitPermit {
    TransmitPermit::for_source(&sipnab::capture::CaptureSource::Live {
        device: "lo".to_string(),
    })
    .expect("a live source grants a transmit permit")
}

/// How the tests start the worker: the `sipnab` binary cargo built for this
/// run (this file's own executable is a test harness), quiet on stderr.
fn spawn_config(rate_limit: u32) -> KillWorkerSpawn {
    KillWorkerSpawn {
        program: env!("CARGO_BIN_EXE_sipnab").into(),
        rate_limit: Some(rate_limit),
        run_as: None,
        log_level: "warn".to_string(),
    }
}

/// Start a worker with the ephemeral sockets only (no raw socket).
fn spawn_worker(rate_limit: u32) -> ScannerKillHandle {
    spawn_scanner_kill_worker(&spawn_config(rate_limit), None, live_permit())
        .expect("the worker process starts")
}

/// A UDP listener on 127.0.0.1 standing in for the scanner — the only thing
/// any test here sends to.
fn scanner() -> (UdpSocket, u16) {
    let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the scanner");
    listener
        .set_read_timeout(Some(test_timeout(10)))
        .expect("read timeout");
    let port = listener.local_addr().expect("local addr").port();
    (listener, port)
}

/// A kill response aimed at the scanner on 127.0.0.1:`port`.
fn kill_to(port: u16, body: &[u8]) -> KillRequest {
    KillRequest::SendResponse {
        dst_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        dst_port: port,
        src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        src_port: 5060,
        response_bytes: body.to_vec(),
    }
}

/// Poll `f` until it yields or `deadline` passes.
fn within<T>(deadline: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let until = Instant::now() + deadline;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Send `signal` to `pid`.
fn signal(pid: u32, signal: libc::c_int) {
    let pid = libc::pid_t::try_from(pid).expect("a pid fits pid_t");
    // SAFETY: kill(2) on a worker the handle under test spawned and has not
    // reaped (the handle holds the Child); touches no memory.
    let rc = unsafe { libc::kill(pid, signal) };
    assert_eq!(rc, 0, "kill({pid}, {signal}) failed");
}

/// The one-letter scheduler state of `pid`, from `/proc/<pid>/stat`.
fn proc_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The state follows the parenthesized command name, which may itself
    // contain spaces or parentheses.
    stat.rsplit_once(") ")?.1.chars().next()
}

/// Stop the worker and wait until the kernel reports it stopped, so nothing
/// sent afterwards can be answered.
fn stop_worker(handle: &ScannerKillHandle) -> u32 {
    let pid = handle.worker_pid().expect("a running worker has a pid");
    signal(pid, libc::SIGSTOP);
    within(test_timeout(10), || {
        (proc_state(pid) == Some('T')).then_some(())
    })
    .expect("the worker must reach the stopped state");
    pid
}

/// Every `socket:[inode]` this process holds a descriptor for.
fn own_socket_inodes() -> Vec<u64> {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd is readable")
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter_map(|target| {
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect()
}

/// A request goes in, a datagram reaches the scanner through the socket the
/// worker inherited, and the parent books it — class, ledger and the per-path
/// counter the metrics exporter reads.
#[test]
fn the_worker_sends_through_an_inherited_socket_and_the_parent_books_it() {
    let (listener, port) = scanner();
    let body = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
    let mut handle = spawn_worker(10);
    let (_, ephemeral_before) = kill_responses_sent();

    handle
        .send_kill(kill_to(port, body))
        .expect("a fresh worker accepts a request");

    let mut buf = [0u8; 2048];
    let (n, from) = listener
        .recv_from(&mut buf)
        .expect("the kill response must reach the scanner");
    assert_eq!(&buf[..n], body, "delivered verbatim");
    assert_ne!(
        from.port(),
        5060,
        "the ephemeral path sends from sipnab's own port, not the forged one"
    );

    let outcome = within(test_timeout(10), || handle.try_recv_response())
        .expect("the outcome must come back from the worker");
    assert_eq!(
        outcome,
        KillResponse::Sent {
            path: SendPath::Ephemeral
        }
    );
    let counts = handle.counts();
    assert_eq!((counts.accepted, counts.sent), (1, 1), "{counts:?}");
    let (_, ephemeral_after) = kill_responses_sent();
    assert!(
        ephemeral_after > ephemeral_before,
        "the parent's ephemeral counter must move: the metrics exporter reads it \
         here, not in the worker"
    );
    handle.shutdown();
    assert!(!handle.is_alive());
}

/// THE property: after the spawn, this process holds none of the send
/// descriptors it handed over.
///
/// Checked by socket inode, so a descriptor kept under another number — a
/// `dup` the handle forgot, a clone held in a field — is found as surely as
/// the original. And checked while the worker demonstrably still has them:
/// a datagram goes out through the same sockets afterwards.
#[test]
fn the_parent_holds_no_send_descriptor_after_the_spawn() {
    let mut handle = spawn_worker(10);
    let handed = handle.handed_over().to_vec();
    assert!(
        handed.iter().any(|h| h.kind == "udp4"),
        "an unprivileged spawn hands over at least the IPv4 UDP socket: {handed:?}"
    );

    let held = own_socket_inodes();
    for h in &handed {
        assert!(
            !held.contains(&h.inode),
            "this process still holds the {} socket (inode {}) it handed to the \
             worker: the process parsing captured traffic keeps a transmit \
             capability after the spawn",
            h.kind,
            h.inode
        );
    }

    // And the worker is the one holding it: the same socket still sends.
    let (listener, port) = scanner();
    handle
        .send_kill(kill_to(port, b"SIP/2.0 200 OK\r\n\r\n"))
        .expect("accepted");
    let mut buf = [0u8; 256];
    listener
        .recv_from(&mut buf)
        .expect("the worker still sends through what it inherited");
    handle.shutdown();
}

/// Run the worker entry point directly, with the arguments given.
fn run_worker_directly(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg(KILL_WORKER_ARG)
        .args(args)
        .env("SIPNAB_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("run the worker entry point")
}

/// Reaps a directly started worker however the test ends.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = terminate(&mut self.0);
    }
}

/// A worker started with no send descriptor refuses every request: "no
/// permit" and "no descriptor" are one refusal, and it creates no socket of
/// its own to send through instead.
#[test]
fn a_worker_started_with_no_descriptor_refuses_every_request() {
    let (listener, port) = scanner();
    let mut worker = Reaped(run_worker_directly(&[
        "--rate-limit",
        "10",
        "--send-fds",
        "none",
        "--run-as",
        "nobody",
        "--log-level",
        "error",
    ]));
    let mut to_worker = worker.0.stdin.take().expect("stdin");
    let mut from_worker = worker.0.stdout.take().expect("stdout");

    for _ in 0..2 {
        wire::write_frame(&mut to_worker, &kill_to(port, b"SIP/2.0 200 OK\r\n\r\n"))
            .expect("write a request");
        let reply: KillResponse = wire::read_frame(&mut from_worker)
            .expect("read a reply")
            .expect("the worker answers rather than closing");
        match reply {
            KillResponse::Rejected { reason } => assert!(
                reason.contains("no send descriptor"),
                "the refusal must say why: {reason}"
            ),
            other => panic!("a worker with nothing to send through must refuse, got {other:?}"),
        }
    }

    listener
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("short timeout");
    let mut buf = [0u8; 64];
    assert!(
        listener.recv_from(&mut buf).is_err(),
        "a worker with no descriptor must not reach the scanner by any route"
    );

    drop(to_worker);
    let status = within(test_timeout(10), || worker.0.try_wait().ok().flatten())
        .expect("end of stream is the worker's shutdown");
    assert!(status.success(), "an orderly end exits 0: {status:?}");
}

/// A descriptor the plan promises but the slot does not hold stops the
/// worker at startup, rather than being wrapped as a socket.
#[test]
fn a_promised_descriptor_that_is_not_there_stops_the_worker() {
    // Nothing places a socket at the udp4 slot: every descriptor this test
    // process holds is close-on-exec, so the worker starts with only stdio.
    let mut worker = Reaped(run_worker_directly(&[
        "--rate-limit",
        "10",
        "--send-fds",
        "udp4",
        "--run-as",
        "nobody",
        "--log-level",
        "error",
    ]));
    let status = within(test_timeout(10), || worker.0.try_wait().ok().flatten())
        .expect("the worker must refuse to start, not wait for requests");
    assert!(
        !status.success(),
        "adopting a descriptor that is not there must fail: {status:?}"
    );
}

/// A descriptor of the wrong kind at a promised slot stops the worker at
/// startup: wrapping a stream socket as the UDP one would write kill
/// responses into whatever connection it belongs to.
#[test]
fn a_promised_descriptor_of_the_wrong_kind_stops_the_worker() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let stream = std::net::TcpListener::bind("127.0.0.1:0").expect("a stream socket");
    let source = stream.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    command
        .arg(KILL_WORKER_ARG)
        .args([
            "--rate-limit",
            "10",
            "--send-fds",
            "udp4",
            "--run-as",
            "nobody",
            "--log-level",
            "error",
        ])
        .env("SIPNAB_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: runs between fork and exec in the child, calling only dup2,
    // which is async-signal-safe; `stream` is open in this process until
    // after the spawn below.
    unsafe {
        command.pre_exec(move || {
            // The udp4 slot, holding a TCP socket instead.
            if libc::dup2(source, 5) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut worker = Reaped(command.spawn().expect("run the worker entry point"));
    drop(stream);
    let status = within(test_timeout(10), || worker.0.try_wait().ok().flatten())
        .expect("the worker must refuse to start, not wait for requests");
    assert!(
        !status.success(),
        "a stream socket in the udp4 slot must be refused: {status:?}"
    );
}

/// The worker gives up everything it does not need: it sets
/// `PR_SET_NO_NEW_PRIVS`, holds no capability, and is not dumpable.
///
/// Dumpability is read the way an attacker in a sibling process meets it:
/// a non-dumpable process's `/proc/<pid>/fd` is closed to other processes of
/// the same user. Run as root that door is open regardless, so the check is
/// skipped there and the other two still run.
///
/// The capability half cannot discriminate here: an unprivileged test starts
/// the worker with no capability to shed (and this host refuses the user
/// namespace that would grant one). What IS checked is the kernel's own
/// report of the running worker. The parsing of that report is pinned by
/// `capabilities_are_clear_only_when_every_set_reads_zero`.
#[test]
fn the_worker_blocks_escalation_holds_no_capability_and_is_not_dumpable() {
    let mut handle = spawn_worker(10);
    let pid = handle.worker_pid().expect("running");
    // The worker hardens itself after it starts; wait for the flag rather
    // than racing it.
    let status = within(test_timeout(10), || {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        s.lines()
            .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"])
            .then_some(s)
    })
    .expect("the worker must set PR_SET_NO_NEW_PRIVS");
    for set in ["CapPrm:", "CapEff:", "CapInh:"] {
        let line = status
            .lines()
            .find(|l| l.starts_with(set))
            .unwrap_or_else(|| panic!("{set} is reported"));
        assert!(
            line.ends_with("0000000000000000"),
            "the worker must hold no capability: {line}"
        );
    }

    // SAFETY: geteuid(2) takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        let fd_dir = format!("/proc/{pid}/fd");
        let listed = within(test_timeout(10), || {
            std::fs::read_dir(&fd_dir)
                .err()
                .filter(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
        });
        assert!(
            listed.is_some(),
            "{fd_dir} must be closed to this process: a dumpable worker lets any \
             process of the same user take its descriptors"
        );
    }
    handle.shutdown();
}

/// The rate limit the parent chose crosses the exec: the worker enforces the
/// number on its command line, not a default of its own.
#[test]
fn the_rate_limit_crosses_the_exec() {
    /// Send three responses to one scanner through a worker started with
    /// `rate`, and return what it did.
    fn sent_under(rate: u32) -> (u64, u64) {
        let (listener, port) = scanner();
        let mut handle = spawn_worker(rate);
        for _ in 0..3 {
            handle
                .send_kill(kill_to(port, b"SIP/2.0 200 OK\r\n\r\n"))
                .expect("accepted");
        }
        let counts = within(test_timeout(10), || {
            let c = handle.counts();
            (c.outcomes() == 3).then_some(c)
        })
        .expect("all three are answered");
        let mut buf = [0u8; 256];
        for _ in 0..counts.sent {
            listener.recv_from(&mut buf).expect("each send arrives");
        }
        handle.shutdown();
        (counts.sent, counts.rate_limited)
    }
    assert_eq!(
        sent_under(1),
        (1, 2),
        "a worker started with --rate-limit 1 sends one response in the first second"
    );
    assert_eq!(
        sent_under(100),
        (3, 0),
        "and one started with 100 is bounded only by the per-destination cap of 3"
    );
}

/// A worker that is stopped cannot make `send_kill` wait: the queue fills,
/// further requests are refused and counted, and the defense is still armed.
///
/// `send_kill` is called by the capture thread while it holds the dialog and
/// stream write locks, so a wait there stops the capture and every reader of
/// those stores. The flood runs on its own thread behind a deadline, so a
/// regression fails instead of hanging the suite.
#[test]
fn send_kill_never_blocks_while_the_worker_is_stopped() {
    let (_listener, port) = scanner();
    let handle = std::sync::Arc::new(spawn_worker(u32::MAX));
    let pid = stop_worker(&handle);

    let flood = 10_000usize;
    let producer = std::sync::Arc::clone(&handle);
    let (done_tx, done_rx) = crossbeam_channel::bounded::<(usize, usize)>(1);
    std::thread::spawn(move || {
        let (mut accepted, mut refused) = (0, 0);
        for _ in 0..flood {
            match producer.send_kill(kill_to(port, b"SIP/2.0 200 OK\r\n\r\n")) {
                Ok(()) => accepted += 1,
                Err(TrySendError::Full(_)) => refused += 1,
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
        let _ = done_tx.send((accepted, refused));
    });
    let (accepted, refused) = done_rx.recv_timeout(test_timeout(20)).unwrap_or_else(|_| {
        panic!(
            "send_kill blocked behind a stopped worker: {flood} offers did not \
             return. In production the caller is the capture thread, holding the \
             dialog and stream write locks."
        )
    });
    assert!(refused > 0, "a stopped worker must fill the queue");
    let counts = handle.counts();
    assert_eq!(counts.dropped_requests, refused as u64, "{counts:?}");
    assert_eq!(accepted + refused, flood, "nothing vanished: {counts:?}");
    assert!(
        !handle.defense_disabled(),
        "a stopped worker is backpressure, not a death"
    );
    assert!(handle.is_alive(), "stopped is not dead");

    signal(pid, libc::SIGCONT);
}

/// Shutdown is bounded even when the worker will not exit: it is killed after
/// the grace period, reaped, and everything it never answered is counted.
#[test]
fn shutdown_ends_a_worker_that_will_not_exit_and_counts_what_it_held() {
    let (_listener, port) = scanner();
    let mut handle = spawn_worker(10);
    stop_worker(&handle);
    for _ in 0..5 {
        handle
            .send_kill(kill_to(port, b"SIP/2.0 200 OK\r\n\r\n"))
            .expect("accepted");
    }

    let started = Instant::now();
    handle.shutdown();
    assert!(
        started.elapsed() < test_timeout(30),
        "shutdown must be bounded: it took {:?}",
        started.elapsed()
    );
    assert!(handle.worker_pid().is_none(), "the worker is reaped");
    assert!(!handle.is_alive());
    let counts = handle.counts();
    assert_eq!(counts.accepted, 5, "{counts:?}");
    assert_eq!(
        counts.accepted,
        counts.outcomes() + counts.lost_to_worker_exit,
        "every accepted request is accounted for: {counts:?}"
    );
    assert!(counts.lost_to_worker_exit > 0, "{counts:?}");
}

/// A worker killed mid-run disables the defense on its own, counts what it
/// held, refuses further requests without blocking, and nothing restarts it.
#[test]
fn a_killed_worker_disables_the_defense_and_counts_what_was_in_flight() {
    let (_listener, port) = scanner();
    let mut handle = spawn_worker(10);
    let pid = stop_worker(&handle);
    for _ in 0..4 {
        handle
            .send_kill(kill_to(port, b"SIP/2.0 200 OK\r\n\r\n"))
            .expect("accepted");
    }
    signal(pid, libc::SIGKILL);

    let counts = within(test_timeout(10), || {
        handle.defense_disabled().then(|| handle.counts())
    })
    .expect("the worker's death must disable the defense without a send failing first");
    assert_eq!(counts.accepted, 4, "{counts:?}");
    assert_eq!(
        counts.lost_to_worker_exit, 4,
        "the four it never answered are lost with it: {counts:?}"
    );
    assert!(!handle.is_alive(), "a killed worker is not alive");

    let refused = handle.send_kill(kill_to(port, b"SIP/2.0 200 OK\r\n\r\n"));
    assert!(
        matches!(refused, Err(TrySendError::Disconnected(_))),
        "a request after the death is refused, not queued for nobody: {refused:?}"
    );
    assert!(!handle.is_alive(), "and nothing restarted it");
    handle.shutdown();
    assert_eq!(
        handle.counts().accepted,
        4,
        "the refused request was never accepted"
    );
}

/// The worker starts before every step of `bootstrap::launch` that could stop
/// an exec: the chroot (which hides the binary and its loader), the Landlock
/// path sandbox (which need not grant execute on the binary) and the seccomp
/// filter (an enforcing list derived from a capture need not allow `execve`
/// at all).
///
/// Read from the source because none of those can be driven here: a chroot
/// needs root, this host's kernel has no Landlock, and an enforcing seccomp
/// list is per host. Placed after any of them, the spawn fails on exactly the
/// hardened deployments, and the defense is off where it matters most.
#[test]
fn the_worker_starts_before_anything_that_could_stop_an_exec() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/bootstrap.rs"))
        .expect("read bootstrap.rs");
    let start = src.find("pub fn launch(").expect("launch is defined");
    let body = &src[start..];
    let body = &body[..body.find("\n}\n").expect("launch ends")];
    // Code only: a comment naming a step is not a call to it.
    let code: String = body
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let at = |call: &str| {
        code.find(call)
            .unwrap_or_else(|| panic!("launch no longer calls {call}; repoint this test"))
    };
    let spawn = at("spawn_kill_worker(");
    for step in [
        "privilege::do_chroot(",
        "install_path_sandbox(",
        "install_syscall_logging(",
    ] {
        assert!(
            spawn < at(step),
            "the kill worker must be started before {step}: after it, the exec \
             the worker needs can be refused, and the defense is off on exactly \
             the hardened runs"
        );
    }
}

/// Reads whatever `child` writes on stderr into a channel, line by line.
///
/// Gated with its only caller: without `hep` it is dead code, and the feature
/// matrix builds every test with `-D warnings`.
#[cfg(feature = "hep")]
fn stderr_lines(child: &mut Child) -> crossbeam_channel::Receiver<String> {
    let stderr = child.stderr.take().expect("stderr piped");
    let (tx, rx) = crossbeam_channel::unbounded();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// End to end, through the real run: `bootstrap::launch` starts the worker,
/// the parent holds none of its descriptors, a HEP-carried request from a
/// `-K` target is answered through the worker, and when the worker is killed
/// the capture carries on without it.
///
/// HEP is the one live source an unprivileged test can open, and `-K` is the
/// kill path with no detection threshold in front of it. The HEP inner source
/// address — where the response goes — is 127.0.0.1 and the test's own
/// listener's port.
#[cfg(feature = "hep")]
#[test]
fn a_real_run_answers_through_its_worker_and_survives_losing_it() {
    use sipnab::capture::hep::{HepEndpoint, HepProtocol, build_hep_v3};

    let (listener, scanner_port) = scanner();
    let hep_port = {
        let s = UdpSocket::bind("127.0.0.1:0").expect("pick a port");
        s.local_addr().expect("addr").port()
    };
    let bind = format!("127.0.0.1:{hep_port}");
    let home = tempfile::tempdir().expect("tempdir");
    let mut command = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    // Start the run holding two stray descriptors WITHOUT close-on-exec, the
    // way a C library's descriptor would sit in it: 3 is a slot the plan
    // leaves empty under --kill-spoof ephemeral, 9 is above the slots. The
    // worker must inherit neither.
    let null = std::fs::File::open("/dev/null").expect("open /dev/null");
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let source = null.as_raw_fd();
        // SAFETY: runs between fork and exec in the child, calling only dup2,
        // which is async-signal-safe; `source` is open in this process for
        // the duration of the spawn because `null` is dropped only after it.
        unsafe {
            command.pre_exec(move || {
                for stray in [3, 9] {
                    if libc::dup2(source, stray) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    let mut run = Reaped(
        command
            .args([
                "-N",
                "--hep-listen",
                &bind,
                "--hep-parse",
                "--hep-allow-kill",
                "-K",
                "127.0.0.1",
                "--kill-spoof",
                "ephemeral",
            ])
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            // Stands in for a bearer token or signing key the run was given
            // through its environment. The worker must not inherit it.
            .env("SIPNAB_PI2_CANARY", "1")
            .env("NO_COLOR", "1")
            .env("SIPNAB_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start sipnab"),
    );
    drop(null);
    let parent = run.0.id();
    let lines = stderr_lines(&mut run.0);
    let mut seen: Vec<String> = Vec::new();
    let mut wait_for = |what: &str, pred: &dyn Fn(&str) -> bool| -> String {
        let until = Instant::now() + test_timeout(30);
        loop {
            if let Some(line) = seen.iter().find(|l| pred(l)) {
                return line.clone();
            }
            let left = until.saturating_duration_since(Instant::now());
            match lines.recv_timeout(left) {
                Ok(line) => seen.push(line),
                Err(_) => panic!("never saw {what}; stderr so far:\n{}", seen.join("\n")),
            }
        }
    };

    let ready = wait_for("the worker's ready line", &|l| {
        l.contains("scanner-kill worker process") && l.contains("ready")
    });
    let worker: u32 = ready
        .split("scanner-kill worker process ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|pid| pid.parse().ok())
        .unwrap_or_else(|| panic!("no pid in {ready}"));
    let status = std::fs::read_to_string(format!("/proc/{worker}/status")).expect("worker status");
    assert!(
        status.contains(&format!("PPid:\t{parent}")),
        "the worker must be the run's own child process"
    );

    // Its descriptors, as the worker reports them, are absent from the run.
    let inodes: Vec<u64> = ready
        .split("socket:[")
        .skip(1)
        .filter_map(|s| s.split(']').next()?.parse().ok())
        .collect();
    assert!(
        !inodes.is_empty(),
        "the worker must report the sockets it holds: {ready}"
    );
    // And it holds stdio and those sockets, and nothing else: not the stray
    // descriptors the run was started with.
    let open: Vec<u32> = ready
        .split("open descriptors [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .map(|list| {
            list.split(", ")
                .filter_map(|fd| fd.trim().parse().ok())
                .collect()
        })
        .unwrap_or_else(|| panic!("no descriptor inventory in {ready}"));
    let mut expected: Vec<u32> = vec![0, 1, 2];
    expected.extend(
        ready
            .split("=fd")
            .skip(1)
            .filter_map(|s| s.split_whitespace().next()?.parse::<u32>().ok()),
    );
    expected.sort_unstable();
    assert_eq!(
        open, expected,
        "the worker must inherit stdio and its send descriptors only; the run's \
         stray descriptors 3 and 9 must not reach it: {ready}"
    );
    // Nor the run's environment: only the worker's own few variables.
    let environment = ready
        .split("environment [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .unwrap_or_else(|| panic!("no environment inventory in {ready}"));
    assert!(
        !environment.contains("SIPNAB_PI2_CANARY"),
        "the worker inherited the run's environment: {environment}"
    );
    assert!(
        environment.contains("SIPNAB_LOG"),
        "the worker's log filter must still cross: {environment}"
    );
    let parent_fds: Vec<String> = std::fs::read_dir(format!("/proc/{parent}/fd"))
        .expect("the run's descriptors are readable to its own user")
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .map(|t| t.display().to_string())
        .collect();
    for inode in &inodes {
        assert!(
            !parent_fds.contains(&format!("socket:[{inode}]")),
            "the capturing process still holds the worker's socket {inode}"
        );
    }

    // Wait for the HEP listener, then deliver a request from the -K target.
    within(test_timeout(30), || {
        let needle = format!("0100007F:{hep_port:04X}");
        std::fs::read_to_string("/proc/net/udp")
            .ok()
            .filter(|t| t.lines().any(|l| l.contains(&needle)))
    })
    .expect("the HEP listener binds");
    let send_options = |n: u32| {
        let sip = format!(
            "OPTIONS sip:probe@127.0.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:{scanner_port};branch=z9hG4bKpi2{n}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:probe@127.0.0.1>;tag=pi2{n}\r\n\
             To: <sip:probe@127.0.0.1>\r\n\
             Call-ID: pi2-{n}@127.0.0.1\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n"
        );
        let endpoint = HepEndpoint {
            src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: scanner_port,
            dst_port: 5060,
            transport: sipnab::net::TransportProto::Udp,
        };
        let hep = build_hep_v3(
            &endpoint,
            chrono::Utc::now(),
            HepProtocol::Sip,
            0,
            None,
            sip.as_bytes(),
        );
        UdpSocket::bind("127.0.0.1:0")
            .expect("sender")
            .send_to(&hep, &bind)
            .expect("send HEP");
    };
    send_options(1);
    let mut buf = [0u8; 2048];
    let (n, _) = listener
        .recv_from(&mut buf)
        .expect("the run must answer the -K target through its worker");
    let answer = String::from_utf8_lossy(&buf[..n]);
    assert!(answer.starts_with("SIP/2.0 "), "a SIP response: {answer}");
    assert!(
        answer.contains("pi2-1@127.0.0.1"),
        "to that request: {answer}"
    );

    // Kill the worker. The run says the defense is off, and keeps capturing.
    signal(worker, libc::SIGKILL);
    wait_for("the defense being reported disabled", &|l| {
        l.contains("DISABLED") && l.contains("scanner-kill worker process is gone")
    });
    send_options(2);
    listener
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("short timeout");
    assert!(
        listener.recv_from(&mut buf).is_err(),
        "nothing restarts the worker, so nothing answers any more"
    );
    assert!(
        run.0.try_wait().expect("try_wait").is_none(),
        "the capture must survive losing its worker"
    );

    let status = terminate(&mut run.0).expect("stop the run");
    assert!(
        status.success(),
        "a run that lost its worker still exits cleanly: {status:?}"
    );
    // The one request the worker took is on the books exactly once. Which
    // class depends on a race this test cannot close: the datagram reaches
    // the scanner BEFORE the worker's report of it reaches the run, so a kill
    // that lands between the two leaves a sent response booked as lost with
    // the worker. Either is honest -- the run cannot know which happened --
    // and neither may be missing.
    let totals = wait_for("the shutdown totals", &|l| {
        l.contains("Scanner-kill totals:")
    });
    let count_before = |label: &str| -> u64 {
        let at = totals
            .find(label)
            .unwrap_or_else(|| panic!("no {label:?} in {totals}"));
        totals[..at]
            .split_whitespace()
            .last()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no count before {label:?} in {totals}"))
    };
    let sent = count_before(" sent");
    let lost = if totals.contains(" lost with the worker process") {
        count_before(" lost with the worker process")
    } else {
        0
    };
    assert_eq!(
        sent + lost,
        1,
        "the request the worker took must be booked once, as sent or lost: {totals}"
    );
}
