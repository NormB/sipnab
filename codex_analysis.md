# Adversarial security analysis of sipnab

**Reviewed revision:** `698585e6807ecb85320aca0d16854e37f083ed68` (2026-07-22)  
**Review date:** 2026-07-22  
**Scope:** Rust application and workspace crate, runtime configuration, network listeners, file outputs, helper scripts, and dependency manifest/lockfile. Generated website assets, demo captures, and the prebuilt release binary were not reverse engineered.

## Executive summary

The strongest practical attack chain is the trust mismatch at the HEP boundary. A HEP UDP sender is allowed to assert arbitrary original source and destination addresses, but sipnab does not authenticate incoming HEP packets. Those asserted addresses subsequently become authoritative packet metadata. In passive analysis this permits capture poisoning; when scanner-kill is enabled it can make sipnab transmit a SIP response to an attacker-selected unicast address. The CIDR allowlist limits who may submit packets but is optional and is based only on the outer UDP source, so it does not validate the inner asserted endpoints.

Two additional defense gaps were found: the standalone metrics listener permits an unauthenticated non-loopback bind, unlike the REST and MCP listeners, and crash reports are created with a follow-symlinks, overwrite-capable API. The latter is low severity under the default per-user directory but becomes dangerous when a privileged deployment selects a shared or attacker-writable report directory.

No hard-coded production credential was found in the reviewed text sources. The API and MCP HTTP transports have good fail-closed non-loopback authentication policies, use constant-time credential verification, and avoid trusting forwarding headers. Packet parsers have extensive fuzz coverage and several explicit size/resource bounds. Event-exec data is passed through environment variables instead of being interpolated into its configured shell command.

## Remediation status (2026-07-22)

All three findings and the hardening opportunities below were addressed on the
same day, test-driven. Summary:

| ID | Status | Key change |
|----|--------|------------|
| SN-01 | **Fixed** | Receiver-side HEP auth (`--hep-auth`/`--hep-auth-file`, constant-time); non-loopback HEP bind refused without auth or allowlist; HEP-origin packets ineligible for scanner-kill unless `--hep-allow-kill`; per-peer rate limiter (`--hep-rate-limit-per-peer`). |
| SN-02 | **Fixed** | Non-loopback metrics bind refused without auth; bounded-concurrency handling (16 slots, `503` when full); `--metrics-auth-file`; CLI example changed to loopback. |
| SN-03 | **Fixed** | Crash reports created with `O_CREAT\|O_EXCL\|O_NOFOLLOW`, mode `0600`; new report dirs `0700`; retry on name collision. |
| Secret-in-argv | **Fixed** | File-backed `--hep-auth-file` / `--metrics-auth-file`. |
| Per-peer HEP limiter | **Fixed** | Per-peer bucket + global ceiling. |

Verification: `cargo test --all-features` (all suites green except one pre-existing,
environment-specific `privilege` test unrelated to these changes) and
`cargo clippy --all-features --all-targets -- -D warnings` (clean). The pre-push
git hook was upgraded to run that clippy gate as a hard block, mirroring CI.

## Findings

### SN-01 — Unauthenticated HEP metadata can drive active network responses

**Severity:** High when HEP and scanner-kill are combined; Medium for HEP-only deployments  
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-940 (Improper Verification of Source of a Communication Channel), CWE-406 (Insufficient Control of Network Message Volume / reflection)  
**Impact framing:** the active-response primitive is a single, rate-limited, spoofed SIP/UDP packet reflected at an attacker-chosen address — packet reflection plus telemetry poisoning, *not* SSRF in the fetch-an-internal-resource sense (no response is read back and no internal service is reached).  
**Affected code:** `src/capture/hep.rs:788-889`, `src/capture/hep.rs:202-340`, `src/app/batch.rs:1264-1311`, `src/process_isolation.rs:479-578`

The HEP listener receives UDP datagrams and applies only an optional outer-source CIDR allowlist and a global rate limit. It then parses the HEP-provided source address, destination address, and ports and installs them as `PreParsed` packet metadata. There is no receiver-side verification of the HEP authentication-key chunk, despite `--hep-auth` existing for the HEP sender.

Scanner detection and targeted kill consume the resulting SIP message and packet endpoints. A generated `KillRequest` reverses those endpoints to send a response to the asserted packet source. The worker rejects broadcast/multicast and rate-limits globally/per destination, but it accepts arbitrary unicast destinations. With a raw socket it additionally forges the response source address; otherwise it still sends from an ephemeral UDP port.

An attacker who can reach the HEP socket can therefore submit a valid HEP packet containing:

1. an attacker-selected unicast address as the encapsulated SIP source;
2. an address/port under the attacker's control or otherwise plausible as the encapsulated destination;
3. a SIP request shaped to trigger scanner detection, or an asserted source matching a configured `--kill-target`.

This poisons dialog/security telemetry and, where an active kill mode is enabled, causes outbound traffic to the selected address. Existing rate limits reduce volume but do not restore destination authority. An outer-source allowlist helps only if every allowed HEP producer and its path are trusted; it does not bind inner metadata to the producer.

**Recommended remediation:**

- Implement receiver-side HEP authentication and reject missing/invalid authentication chunks when a secret is configured. Compare secrets in constant time.
- Refuse non-loopback HEP binds unless either authentication or a non-empty allowlist is configured, paralleling the API/MCP policy.
- Treat HEP-originated packets as ineligible for active scanner-kill by default. Require an explicit opt-in, and constrain outbound destinations to configured CIDRs or verified mappings from HEP sender identity to permitted inner networks.
- Record outer peer and inner endpoints separately and include both in alerts/audit logs.
- Add an integration test proving a forged inner source from HEP cannot cause a kill response without the explicit active-response policy.

**Resolution (Fixed):**

- Receiver-side authentication added. `parse_hep_v3` now captures the `0x000e`
  auth-key chunk into `HepPacket.auth_key`; the listener compares it against the
  configured secret in constant time via `hep_auth_ok` (`crate::crypto::constant_time_eq`)
  and drops missing/invalid packets (`src/capture/hep.rs`). The secret comes from
  `--hep-auth` / `--hep-auth-file` / `SIPNAB_HEP_AUTH`.
- `enforce_hep_bind_policy` refuses a non-loopback `--hep-listen` bind unless a
  secret or a non-empty `--hep-allow` list is configured, mirroring the API/MCP D18 rule.
- HEP-origin packets are now flagged (`ParsedPacket.from_hep`, set in the
  `pre_parsed` branch of `parse_packet`) and are **ineligible for scanner-kill by
  default**. `scanner_kill::kill_response_eligible(from_hep, hep_allow_kill)` gates
  both kill sites in `src/app/batch.rs`; re-enabling requires the explicit
  `--hep-allow-kill` opt-in.
- The rate limiter now enforces a per-peer cap plus the global ceiling
  (`--hep-rate-limit-per-peer`), so one sender cannot starve others.
- Tests: `parse_captures_auth_key_chunk`, `verify_hep_auth_*`, `hep_bind_policy_*`,
  `per_peer_limiter_*` (hep.rs); `parse_packet_flags_pre_parsed_as_from_hep`,
  `parse_packet_normal_capture_is_not_from_hep` (parse.rs);
  `kill_eligibility_blocks_unauthed_hep_by_default` (scanner_kill.rs).

### SN-02 — Standalone metrics can be exposed without authentication

**Severity:** Medium  
**CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-770 (Allocation of Resources Without Limits or Throttling)  
**Affected code:** `src/output/prometheus_server.rs:28-151`, `src/app/bootstrap.rs:214-223`, `src/app/tui_mode.rs:87-103`, `src/cli.rs:584-593`

The standalone metrics server binds any operator-supplied `SocketAddr`; authentication is optional regardless of whether the address is loopback. This differs from the REST API and MCP HTTP transports, both of which refuse unauthenticated non-loopback binds. The CLI help itself advertises `0.0.0.0:9090` as the metrics example without warning that `--metrics-auth` is needed.

An exposed endpoint leaks operational capture information (dialog/message/stream counts, security-event counters, capture pressure, and scanner-kill activity). More importantly, the server is a single blocking accept loop with no request-rate or connection limit. Five-second read/write timeouts bound each connection, but a remote client can repeatedly occupy the sole worker and make monitoring unavailable.

This requires the operator to explicitly request a non-loopback bind, so it is not a default remote exposure.

**Recommended remediation:**

- Reject non-loopback metrics binds when `metrics_auth` is absent, with an explicit escape hatch only if unauthenticated publication is a supported use case.
- Prefer a token-file option over `user:pass` on the command line/config, and document TLS termination because Basic credentials are only encoded, not encrypted.
- Add connection concurrency and request-rate limits, or serve metrics through the already-hardened HTTP stack when that feature is available.
- Change CLI examples to loopback and add regression tests for bind-policy enforcement.

**Resolution (Fixed):**

- `start_metrics_server` now refuses a non-loopback bind when `basic_auth` is
  absent and warns (TLS reminder) when bound non-loopback with auth
  (`src/output/prometheus_server.rs`).
- A `ConnGate` bounds concurrent handlers to 16; connections beyond the cap get
  an immediate `503` and close, and each accepted connection is handled on its
  own short-lived thread so one slow client no longer blocks the accept loop.
- `--metrics-auth-file` reads the credential from a file (out of the process list),
  taking precedence over `--metrics-auth`.
- CLI help example changed from `0.0.0.0:9090` to `127.0.0.1:9090` with a note.
- Tests: `refuses_non_loopback_bind_without_auth`, `allows_non_loopback_bind_with_auth`,
  `allows_loopback_bind_without_auth`, `conn_gate_caps_and_releases`
  (prometheus_server.rs); `resolve_secret_*` (cli.rs).

### SN-03 — Crash report creation permits symlink overwrite in unsafe report directories

**Severity:** Low (potentially High in a privileged/shared-directory deployment)  
**CWE:** CWE-59 (Improper Link Resolution Before File Access), CWE-377 (Insecure Temporary File)  
**Affected code:** `src/crash.rs:89-107`

`write_crash_report` constructs a partially predictable name from the current UTC second, PID, and a process-local counter, then calls `std::fs::write`. That API creates or truncates the destination and follows a pre-existing symlink. If the configured crash directory is writable by another user, that user can pre-create candidate names as symlinks. A subsequent panic in a privileged sipnab process may overwrite a file selected by the attacker with crash-report text.

The default directory is under the invoking user's state directory and normally avoids the prerequisite. The risk appears when `report_dir` is set to `/tmp`, another shared directory, or a directory whose ownership/mode is not controlled. `create_dir_all` does not verify ownership or reject a pre-existing symlink in the directory path.

**Recommended remediation:**

- Open the report with `OpenOptions::create_new(true)` (and `O_NOFOLLOW` on Unix), retrying with cryptographically random suffixes on collision.
- On Unix, create reports mode `0600` and newly created report directories mode `0700`.
- Validate that the final report directory is owned by the effective user and is not group/world writable; document this invariant for privileged services.
- Add a Unix regression test that plants a symlink at the predicted target and confirms the linked file is not modified.

**Resolution (Fixed):**

- `write_crash_report` now creates the file through `open_new_report_file`, which
  uses `OpenOptions::create_new(true)` plus `O_NOFOLLOW` and mode `0600` on Unix, so
  a pre-planted symlink or existing file is refused rather than followed/overwritten.
  It retries with a fresh sequence suffix on collision (`src/crash.rs`).
- `create_report_dir` sets a newly created report directory to `0700` on Unix.
- Tests: `open_new_report_refuses_to_follow_symlink`, `open_new_report_refuses_existing_file`,
  `crash_report_created_mode_0600` (crash.rs).

Note: the recommended report-directory ownership/mode *validation* is not yet
enforced at runtime (the `0600`/`0700` creation modes and `O_NOFOLLOW` close the
symlink-overwrite vector regardless of directory ownership); documenting the
shared-directory invariant for privileged services remains a follow-up.

## Additional observations and hardening opportunities

- `--metrics-auth user:pass`, static API/MCP secrets, HEP sender secrets, and signing keys may be supplied directly as command-line arguments. On systems where process arguments are visible to other users or telemetry, prefer file-backed secret options. API/MCP already support several file-based paths; equivalent options should be consistent across listeners. **Fixed:** added `--hep-auth-file` and `--metrics-auth-file` (both take precedence over their inline forms, contents trimmed, empty/unreadable file is a hard error via `resolve_file_or_inline_secret`).
- The audio plugin loader eventually attempts a bare platform filename after explicit and fixed paths (`src/rtp/playback.rs:178-224`). This broadens dynamic-library search behavior. The plugin is normally loaded after privilege drop, substantially limiting impact, but fixed absolute installation paths plus ownership/permission checks would make the trust claim enforceable. **Deferred:** left unchanged — the privilege-drop mitigation stands, and constraining the search path risks breaking platform-specific plugin discovery; tracked as a follow-up.
- HEP's packet-rate limiter is global rather than per peer. One reachable sender can consume the allowance and starve legitimate producers. A per-peer bucket plus a global ceiling would provide fairer overload behavior. **Fixed:** `HepRateLimiter` now tracks a per-peer count (bounded to 4096 tracked peers) alongside the global ceiling; the per-peer cap is set via `--hep-rate-limit-per-peer` (default off for the common single-collector topology).
- `/health` is deliberately unauthenticated and un-rate-limited. Its fixed response exposes little, but it can still be used for request-volume pressure. Infrastructure-level connection limits remain advisable. **Deferred:** unchanged by design (documented as reverse-proxy/infrastructure concern).

## Positive controls observed

- REST and MCP HTTP reject unauthenticated non-loopback binding.
- REST rate limiting keys on the TCP peer and explicitly ignores attacker-controlled forwarding headers.
- Bearer/static-secret and standalone Basic-auth comparisons are implemented in constant time; signed tokens support expiry, rotation, and revocation.
- Event-exec templates are operator-controlled, while captured SIP values are passed as environment variables rather than interpolated into the shell command.
- Capture queues, dialog/stream stores, TCP reassembly, response shaping, WebSocket lengths, and pcapng metadata have explicit bounds in relevant paths.
- Scanner-kill rejects multicast/broadcast destinations and has global and per-destination limiting.
- Root live-capture mode drops supplementary groups, GID, and UID before packet processing and sets `no_new_privs` on Linux.
- Parser-facing components have broad cargo-fuzz targets (SIP, SDP, RTP/RTCP, TLS/DTLS, HEP, WebSocket, pcap, reassembly, filter DSL, and STIR/SHAKEN).

## Method and limitations

This was a source-assisted adversarial review. It traced untrusted data from packet files and network listeners into parsers, stores, APIs, shell/process boundaries, filesystem writes, dynamic loading, and active network sends. It also searched for unsafe Rust, panic sites, hard-coded secrets, unbounded input, authentication decisions, and path-handling patterns. `cargo test --all-features --no-run` completed successfully, confirming that the reviewed all-features configuration and its test targets compile.

This was not a formal proof, sustained fuzzing campaign, live network penetration test, package-signature audit, or reverse engineering of the checked-in binary/WASM. Severity assumes a conventional deployment and should be adjusted for actual reachability, privilege, configuration, and network egress controls.
