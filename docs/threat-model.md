# Threat model and security assessment

This page answers three questions about sipnab: what an attacker would want
from it, where an attacker can reach it, and what stops them. It also lists
what does *not* stop them. The last section, residual risks, matters as much
as the rest: an assessment that lists only defenses tells an operator nothing
about where to add their own.

[`SECURITY.md`](https://github.com/NormB/sipnab/blob/main/SECURITY.md) says how
to report a vulnerability and which classes of bug count as one. This page is
the analysis behind that list.

## Terms used on this page

- **Asset**: something worth protecting, such as a TLS private key or the
  calls in a capture.
- **Trust boundary**: a place where data or commands cross from something
  sipnab does not control into sipnab. Every input an attacker can influence
  crosses one.
- **Threat**: a specific thing an attacker could try at a boundary.
- **Mitigation**: the code that makes a threat fail or limits its damage. Every
  mitigation below names the file, and usually the function, that implements
  it, so a reader can check the claim instead of trusting it.
- **Residual risk**: a threat that no mitigation fully covers today.
- **Loopback**: the `127.0.0.1` or `::1` address, reachable only from the same
  machine.
- **Bearer token**: a secret a client sends in an HTTP `Authorization: Bearer`
  header. Whoever holds the token has the access it grants.
- **HMAC**: a keyed checksum. Only a holder of the key can produce a value that
  verifies, so it proves who sent a message and that nobody changed it.

## Scope and method

The assessment covers the `sipnab` binary built with the `full` feature set
on Linux, which is the build that has every listener and every hook. It walks
each trust boundary, names the likely threats there, and cites the code that
answers each one. The authors read each cited function to confirm it does what
this page says. Where the code does less than a reader might assume, the gap
appears under [residual risks](#residual-risks-and-known-gaps).

sipnab is mostly passive: it reads packets and reports on them. Two features
act on other systems, scanner-kill (sends SIP responses) and the TFPS ban
actions. Both are off by default.

## Assets

| Asset | Why an attacker wants it |
|---|---|
| Captured SIP and RTP | Call metadata (who called whom, when), SIP digest credentials, and call audio. |
| Decryption secrets | TLS private keys (`--tls-key`), TLS key logs (`--keylog`), SRTP keys, and secrets embedded in pcapng files. Any of these decrypts traffic beyond what sipnab shows. |
| Credentials sipnab checks | REST API keys and signing keys, MCP tokens, metrics Basic-auth credentials, HEP shared secrets, archive passwords. |
| The capture host | sipnab often starts as root to open a network device. Code execution in sipnab before the privilege drop is code execution as root. |
| Integrity of findings | Security alerts, scanner-kill decisions and fail2ban lines drive action elsewhere. Forged findings can ban an innocent address. |
| Other networks | The scanner-kill path transmits. Misused, it could aim traffic at a victim. |
| Evidence files | A capture is often the only copy of an incident. Overwriting it destroys evidence. |

## Trust boundaries at a glance

| Boundary | Who is on the other side | Exposure by default |
|---|---|---|
| [Packet capture input](#packet-capture-input-live-interfaces) | Anyone who can send a packet the capture interface sees | Whenever sipnab captures live |
| [Capture and archive files](#capture-and-archive-files) | Whoever produced the file | Whenever `-I` reads a file |
| [HEP senders](#hep-senders) | Any host that can reach the HEP port | Off. `--hep-listen` turns it on |
| [REST API clients](#rest-api-and-metrics-clients) | Any host that can reach the API port | Off. `--api` turns it on |
| [MCP clients](#mcp-clients) | An AI agent and whoever controls its prompts | Off. `--mcp` turns it on |
| [Exec hooks](#commands-run-by-exec-hooks) | Contents of captured SIP, passed to an operator's command | Off. `--on-dialog-exec`, `--on-quality-exec` and `--alert-exec` turn it on |
| [WASM plugins](#wasm-plugins) | The author of a plugin file | Not in the default build. The `plugins` feature adds it |
| [TLS and SRTP key material](#tls-and-srtp-key-material) | Other local users, crash dumps, swap | Whenever a key option is present |
| [Configuration files and the command line](#configuration-files-and-the-command-line) | Anyone who can write a config file or read the process list | Always |

## Packet capture input (live interfaces)

Every packet on a monitored interface is attacker-controlled. A remote attacker
needs no account and no connection, only the ability to send one SIP or RTP
packet that crosses the wire sipnab watches.

| Threat | Mitigation | Where |
|---|---|---|
| A malformed packet crashes a parser or corrupts memory. | The parsers are Rust. The project fuzzes every parser that reads untrusted bytes, and a smoke tier runs in ordinary CI. [Fault model](fault-model.md) counts the `unsafe` blocks and names where they live. | [`fuzz/fuzz_targets/`](https://github.com/NormB/sipnab/tree/main/fuzz/fuzz_targets), [`tests/smoke_fuzz_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/smoke_fuzz_test.rs) |
| A flood of unique Call-IDs or RTP SSRCs grows memory without limit. | The dialog and stream stores cap their size and evict. A regression test floods 50,000 identities into a 1,000-entry store. | [`tests/resource_bounds_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/resource_bounds_test.rs) |
| Oversized header lines, TCP streams or WebSocket frames exhaust memory. | Fixed caps on header-line length, on the reassembly buffer and on WebSocket message size. | [`src/sip/parser.rs::DEFAULT_MAX_HEADER_LINE_LEN`](https://github.com/NormB/sipnab/blob/main/src/sip/parser.rs), [`src/capture/reassembly.rs::DEFAULT_MAX_TCP_BUFFER`](https://github.com/NormB/sipnab/blob/main/src/capture/reassembly.rs), [`src/capture/websocket.rs::MAX_WS_MESSAGE_SIZE`](https://github.com/NormB/sipnab/blob/main/src/capture/websocket.rs) |
| A parser bug becomes root code execution. | Once the capture thread reports the device open, sipnab drops to an unprivileged user (`nobody` unless `--user` names another) and checks that the drop took. See residual risk 10 for the window before the drop. It sets `PR_SET_NO_NEW_PRIVS` at startup so a later `exec` cannot regain privilege. | [`src/privilege.rs::drop_privileges`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs), [`src/privilege.rs::verify_dropped`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs), [`src/privilege.rs::block_privilege_escalation`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs) |
| A forged scanner packet turns scanner-kill into a reflector aimed at a victim. | Responses pass a global per-second cap (default 10, zero refused) and a fixed cap of three per destination per minute that no option raises. Only a live source can create the send sockets: a capture file or a uprobe source cannot. The sockets live in a separate worker process that starts with an emptied environment and clears its Linux capabilities. | [`src/cli.rs::DEFAULT_KILL_RATE_LIMIT`](https://github.com/NormB/sipnab/blob/main/src/cli.rs), [`src/process_isolation.rs::MAX_PER_DST_PER_MINUTE`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs), [`src/security/transmit_guard.rs::for_source`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs), [`src/process_isolation/worker_process.rs::clear_capabilities`](https://github.com/NormB/sipnab/blob/main/src/process_isolation/worker_process.rs) |

## Capture and archive files

A capture file is as hostile as the network it came from, and an archive adds
decompression and file names chosen by its author.

| Threat | Mitigation | Where |
|---|---|---|
| A record header claims a huge length and triggers an out-of-bounds read. | The reader uses checked arithmetic and a bounds check on every record length. | [`src/capture/pcap_reader.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/pcap_reader.rs) |
| A decompression bomb fills memory or disk. | Every byte that decompression produces, summed over every nested layer, counts against one ceiling (default 1 GiB, set with `--max-gunzip-bytes`). Nesting stops at four layers and member count at 10,000. | [`src/capture/pcap_reader.rs::DEFAULT_MAX_GUNZIP_BYTES`](https://github.com/NormB/sipnab/blob/main/src/capture/pcap_reader.rs), [`src/capture/archive/mod.rs::MAX_DEPTH`](https://github.com/NormB/sipnab/blob/main/src/capture/archive/mod.rs), [`src/capture/archive/mod.rs::MAX_ENTRIES`](https://github.com/NormB/sipnab/blob/main/src/capture/archive/mod.rs) |
| A member named `../../etc/cron.d/x` writes outside the extraction directory. | sipnab never uses a member's name as a path. It writes each member to a name it generates (`m00003.pcap`) inside a private temporary directory, creates the file exclusively with owner-only permissions, and never materializes links, device nodes or named pipes. | [`src/capture/archive/mod.rs::ExtractDir`](https://github.com/NormB/sipnab/blob/main/src/capture/archive/mod.rs) |
| An output option points at an input and destroys the evidence. | sipnab compares canonical paths, after resolving symlinks and `..`, and refuses before it opens anything for writing. | [`src/capture/output_guard.rs::canonical_target`](https://github.com/NormB/sipnab/blob/main/src/capture/output_guard.rs) |
| A pcapng file embeds TLS secrets that travel with a shared copy. | sipnab reads Decryption Secrets Blocks so it can decrypt, and `--strip-secrets` writes a copy with every one removed, for use before anyone shares a capture. | [`src/capture/pcapng_meta.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/pcapng_meta.rs), [`src/cli.rs`](https://github.com/NormB/sipnab/blob/main/src/cli.rs) (`strip_secrets`) |
| An archive password leaks through the process list, a URL or a readable file. | `--archive-password` prints a warning naming the safer options on every use. sipnab refuses a password file you own that other users can read. The REST API refuses a password in a query string and limits wrong guesses to five per token and archive in 15 minutes. | [`src/capture/archive/password.rs::INLINE_WARNING`](https://github.com/NormB/sipnab/blob/main/src/capture/archive/password.rs), [`src/capture/archive/password.rs::permission_refusal`](https://github.com/NormB/sipnab/blob/main/src/capture/archive/password.rs), [`src/output/api.rs::refuse_password_in_url_mw`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs), [`src/output/api.rs::ARCHIVE_WRONG_LIMIT`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs) |

## HEP senders

HEP (Homer Encapsulation Protocol) lets a SIP server such as OpenSIPS or
Kamailio mirror its traffic to sipnab over the network. A HEP packet carries
the SIP message *and* the addresses it claims the message used, so a sender
can assert any source address it likes.

| Threat | Mitigation | Where |
|---|---|---|
| Anyone on the network injects fake calls. | A listener on a non-loopback address refuses to start unless it has a shared secret or a source allowlist. It classifies loopback from the literal address only, without a DNS lookup, so a hostname counts as non-loopback. | [`src/capture/hep.rs::enforce_hep_bind_policy`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs) |
| An attacker recovers the shared secret byte by byte from response timing. | The shared secret check compares in constant time. | [`src/capture/hep.rs::plain_auth_check`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs), [`src/crypto.rs::constant_time_eq`](https://github.com/NormB/sipnab/blob/main/src/crypto.rs) |
| An attacker replays or edits a captured HEP packet. | The opt-in `--hep-auth-mode hmac` signs the whole datagram, rejects stale timestamps, and remembers the one-time number (nonce) in each accepted packet to refuse replays. It verifies the signature before touching the nonce cache, so a forged packet cannot poison it. | [`src/capture/hep.rs::verify_hmac_datagram`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs) |
| A sender forges a source address so sipnab kills a call or bans an innocent host. | Scanner-kill and fail2ban lines act on a HEP-reported address only with `--hep-allow-kill`, which defaults off. | [`src/security/scanner_kill.rs::kill_response_eligible`](https://github.com/NormB/sipnab/blob/main/src/security/scanner_kill.rs) |
| A HEP-over-TLS key file readable by every user lets anyone impersonate the listener. | sipnab refuses a world-readable key. | [`src/capture/hep.rs::pem_private_key`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs) |
| One sender floods the listener. | A global packet ceiling (`--hep-rate-limit`, default 50,000 packets per second) and an optional per-sender cap (`--hep-rate-limit-per-peer`, off by default). | [`src/capture/hep.rs::describe_hep_limiters`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs) |

## REST API and metrics clients

The REST API (`--api`) serves everything sipnab knows about the capture. The
metrics endpoint (`--metrics`) serves Prometheus counters.

| Threat | Mitigation | Where |
|---|---|---|
| The API listens on a public address with no credentials. | A non-loopback bind with no API key or signing key refuses to start. The metrics server applies the same rule to its Basic-auth credential. | [`src/output/api.rs::enforce_bind_auth_policy`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs), [`src/output/prometheus_server.rs::start_metrics_server`](https://github.com/NormB/sipnab/blob/main/src/output/prometheus_server.rs) |
| An attacker forges or reuses a token. | Tokens carry an HMAC-SHA256 signature, an expiry, an audience (`api` or `mcp`) and an id that a revocation list can name. Verification compares signatures in constant time. A value that starts like a signed token and fails any check gets a refusal, never a second chance as a static key. [Authentication](auth.md) describes minting and rotation. | [`src/auth.rs::verify_signed`](https://github.com/NormB/sipnab/blob/main/src/auth.rs), [`src/auth.rs::verify_static`](https://github.com/NormB/sipnab/blob/main/src/auth.rs) |
| A token for one surface opens the other. | The audience check is unconditional, so an API token fails on MCP and the reverse. | [`src/auth.rs::verify_signed`](https://github.com/NormB/sipnab/blob/main/src/auth.rs) |
| An attacker guesses tokens at high speed. | The per-client rate limit runs *before* authentication, so a wrong guess costs the same budget as a right one. | [`src/output/api.rs::guard_scoped`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs) |
| A read-only credential triggers a ban on another system. | TFPS ban and unban need a token with the `actions` scope *and* a server-side setting that enables them. | [`src/output/api.rs::action_guard`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs) |
| A slow or huge request ties up the server. | Every route has a 30-second timeout and a 1 MiB body limit. | [`src/output/api.rs::build_router`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs), [`src/output/api.rs::REQUEST_TIMEOUT`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs), [`src/output/api.rs::MAX_REQUEST_BODY_BYTES`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs) |

## MCP clients

MCP (Model Context Protocol) lets an AI agent query sipnab. The agent is a
client like any other, with one extra risk: text inside a capture can reach
the agent's prompt, so a hostile SIP header can try to talk the agent into
calling a tool. The defenses therefore limit what *any* caller can do, rather
than trusting the agent's judgment. [MCP deployment](mcp-deploy.md) covers
running it safely.

| Threat | Mitigation | Where |
|---|---|---|
| The HTTP transport listens on a public address with no credentials. | A non-loopback bind without a token or signing key refuses to start. | [`src/mcp/transport.rs::serve_http`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs) |
| A web page uses DNS rebinding to reach a loopback MCP server through a browser. | Requests must carry a `Host` header on the allowlist (`localhost`, `127.0.0.1` and `::1`, plus `--mcp-allowed-host` entries). | [`src/mcp/transport.rs::serve_http`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs) |
| An agent replaces the capture, installs TLS probes, stops the server or writes findings. | Each of these tools refuses unless the operator started sipnab with its own opt-in flag: `--mcp-allow-open-capture`, `--mcp-allow-tls-capture`, `--mcp-allow-shutdown` and `--mcp-allow-save-findings`. | [`src/mcp/server.rs::open_capture`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs) and the `allow_*` fields beside it |
| An agent writes or reads outside a chosen directory. | File tools accept a bare file name only, resolve symlinks, and refuse any result outside `--mcp-file-root`. With no root set, the file tools refuse. | [`src/mcp/server.rs::resolve_in_root`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs) |
| One agent monopolizes the server. | A per-caller cap on tool calls per second (`--mcp-rate-limit-per-peer`, default 100) and a 2 MiB request body cap. | [`src/mcp/server.rs::with_rate_limit_per_peer`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs), [`src/mcp/transport.rs::serve_http`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs) |

## Commands run by exec hooks

`--on-dialog-exec`, `--on-quality-exec` and `--alert-exec` run an operator's
command when an event fires. The event data comes from captured SIP, so a
caller can choose the From header that reaches the command.

| Threat | Mitigation | Where |
|---|---|---|
| A crafted SIP header injects shell syntax into the command. | sipnab passes event data in `SIPNAB_*` environment variables and never splices it into the command string. The legacy `%from` style placeholders become `$SIPNAB_FROM` references, not text substitution. | [`src/output/event_exec.rs::spawn_command`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs), [`src/output/event_exec.rs::migrate_template_vars`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs), [`src/security/alerting.rs`](https://github.com/NormB/sipnab/blob/main/src/security/alerting.rs) |
| A burst of events forks thousands of processes. | A per-second rate limit and a cap on live child processes (default 100, `[limits] exec_queue_depth`). sipnab drops and counts events past either cap. | [`src/output/event_exec.rs::DEFAULT_QUEUE_DEPTH`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs), [`src/output/event_exec.rs::check_rate_limit`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs) |

## WASM plugins

A plugin is a WebAssembly module that receives one dialog as JSON and returns
findings. The `plugins` feature adds it, and the default build leaves it out.
[WASM plugins](plugins.md) is the author's guide.

| Threat | Mitigation | Where |
|---|---|---|
| A plugin reads files, opens sockets or runs commands. | The host registers no imports at all, so a module that imports anything fails to load. The interpreter, `wasmi`, runs no JIT. | [`src/plugin/mod.rs::instantiate`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs) |
| A plugin loops forever or allocates the host's memory. | A fuel budget per dialog, a 16 MiB memory cap installed *before* the module's declared memory exists, a 4 MiB output cap and a 16 MiB file-size cap. A failing plugin fails that dialog only. | [`src/plugin/mod.rs::FUEL_PER_DIALOG`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs), [`src/plugin/mod.rs::MAX_MEMORY_PAGES`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs), [`src/plugin/mod.rs::MAX_OUTPUT_BYTES`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs), [`src/plugin/mod.rs::MAX_PLUGIN_BYTES`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs) |

## TLS and SRTP key material

sipnab decrypts traffic that other systems encrypted, so it holds keys that
decrypt far more than one capture. [Capture SIP over TLS](tls-capture.md)
covers the options.

| Threat | Mitigation | Where |
|---|---|---|
| A crash writes keys into a core file. | With any key option present, sipnab turns off core dumps for itself (`PR_SET_DUMPABLE`) and exits if that fails, unless `--allow-coredump` says otherwise. | [`src/privilege.rs::disable_core_dumps`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs), [`src/app/bootstrap.rs`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs) |
| The kernel writes keys to swap. | sipnab locks its memory with `mlockall`. If the host's `RLIMIT_MEMLOCK` forbids that, it logs a warning and continues. | [`src/privilege.rs::lock_key_memory`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs) |
| Keys linger in freed memory. | Key-log entries, key-log read buffers and derived SRTP session keys wipe themselves on drop. | [`src/capture/tls.rs::zeroize_material`](https://github.com/NormB/sipnab/blob/main/src/capture/tls.rs), [`src/capture/keylog_source.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/keylog_source.rs), [`src/rtp/srtp.rs::DerivedSessionKeys`](https://github.com/NormB/sipnab/blob/main/src/rtp/srtp.rs) |
| A private key reaches a log line. | The RSA key type prints as `RsaKey(<redacted>)`, and a parse error never echoes key bytes. | [`src/capture/rsa_key.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/rsa_key.rs) |
| A libpcap defect reads another run's key log. | The opt-in Landlock sandbox (`--sandbox best-effort` or `required`) limits which paths the process can open after startup. | [`src/sandbox.rs::install`](https://github.com/NormB/sipnab/blob/main/src/sandbox.rs) |

## Configuration files and the command line

sipnab reads a TOML file from `--config`, `$SIPNAB_CONFIG`,
`~/.config/sipnab/sipnab.toml`, `~/.sipnabrc` or `/etc/sipnab/sipnab.toml`, in
that order. The file can name commands to run (`alert_exec`), so write access
to it amounts to running code as sipnab.

| Threat | Mitigation | Where |
|---|---|---|
| A typo in a key silently disables a setting, such as a rate limit. | sipnab warns about every unknown key, and validation refuses unsafe values such as a zero exec queue or a zero kill rate. | [`src/config.rs::unknown_keys`](https://github.com/NormB/sipnab/blob/main/src/config.rs), [`src/config.rs`](https://github.com/NormB/sipnab/blob/main/src/config.rs) (`validate`) |
| An environment variable in the config expands into more than the config named. | Only the `${NAME}` form expands, never recursively, and an unset variable is an error rather than an empty string. | [`src/config.rs::expand_env_vars`](https://github.com/NormB/sipnab/blob/main/src/config.rs) |
| A secret on the command line shows up in `ps` output. | The listener secrets have file or environment-variable forms, such as `--api-signing-key-file`, `--mcp-token-file`, `--hep-auth-file`, `--metrics-auth-file` and `SIPNAB_API_KEY`. | [`src/cli.rs`](https://github.com/NormB/sipnab/blob/main/src/cli.rs) |

## Hardening that spans every boundary

- **Privilege drop and chroot.** During startup, `--user` sets the account
  sipnab drops to and `--chroot` narrows the filesystem it can see
  ([`src/privilege.rs::do_chroot`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs)).
  [Architecture](architecture.md) explains the privilege-drop design.
- **Landlock path sandbox**, opt-in with `--sandbox`
  ([`src/sandbox.rs`](https://github.com/NormB/sipnab/blob/main/src/sandbox.rs)).
- **Seccomp system-call filter**, opt-in with `--seccomp`. The `log` mode
  records calls and blocks nothing. The `enforce` mode needs an allowlist the
  operator supplies
  ([`src/seccomp.rs`](https://github.com/NormB/sipnab/blob/main/src/seccomp.rs),
  [syscall sandbox design](design/syscall-sandbox.md)).
- **Dependency checks.** `cargo deny` and `cargo audit` run in CI against
  [`deny.toml`](https://github.com/NormB/sipnab/blob/main/deny.toml), and
  Dependabot watches for updates
  ([`.github/dependabot.yml`](https://github.com/NormB/sipnab/blob/main/.github/dependabot.yml)).

## Residual risks and known gaps

Each item below is a threat the code does not fully answer today. Most are
choices with a stated reason, and some are open work. An operator who needs
protection against one of these has to supply it outside sipnab.

1. **No TLS on the REST API or HTTP MCP.** sipnab refuses `--api-tls-cert`
   today and tells the operator to use a reverse proxy
   ([`src/output/api.rs::prepare_listener`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)).
   Both servers log a warning on a non-loopback bind but still start. Without
   a proxy, bearer tokens and capture data cross the network in clear text.
   The metrics endpoint uses Basic auth, which is encoding, not encryption.
2. **Loopback means no authentication.** With no key configured, the REST API
   and HTTP MCP accept every request on a loopback bind
   ([`src/output/api.rs::authenticate`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)).
   On a shared host, every local user can read the capture through them.
3. **Authenticated clients see real data.** `--redact` replaces identities with
   pseudonyms in exported vCon containers only. The REST API and MCP answer
   with the real addresses and identities, and neither calls the redactor
   ([`src/output/redact.rs`](https://github.com/NormB/sipnab/blob/main/src/output/redact.rs)).
4. **Failed MCP logins face no throttle.** The MCP rate limit counts tool calls
   after authentication, and the HTTP bearer check has no limiter of its own
   ([`src/mcp/transport.rs::auth_layer`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs)).
   Signed tokens resist guessing through their 256-bit signature, but a short
   static `--mcp-token` does not.
5. **Plain HEP authentication is weak.** In the default `plain` mode, each
   packet carries the shared secret in clear text, so anyone on the path can
   read and reuse it, and nothing stops replays. The HMAC mode fixes both, but
   only another sipnab sends it. A source allowlist alone trusts UDP source
   addresses, which an attacker can forge.
6. **Exec hooks inherit the environment.** The child processes start with
   sipnab's full environment, including any `SIPNAB_API_KEY` or similar secret
   set there
   ([`src/output/event_exec.rs::spawn_command`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs)).
   Passing data through variables also only helps while the hook script
   quotes them: a script that runs `eval $SIPNAB_FROM` reintroduces the
   injection.
7. **No permission check on most secret files or the config file.** sipnab
   checks permissions on archive password files and the HEP TLS key only. It
   reads signing-key files
   ([`src/app/servers.rs::read_signing_key_file`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs)),
   `--tls-key` and the config file without checking who else can read or
   write them. Whoever can write the config file can set `alert_exec`.
8. **The sandbox and system-call filter are off by default.** Landlock and seccomp both default to
   `off`
   ([`src/sandbox.rs::SandboxMode`](https://github.com/NormB/sipnab/blob/main/src/sandbox.rs),
   [`src/seccomp.rs::SeccompMode`](https://github.com/NormB/sipnab/blob/main/src/seccomp.rs)),
   and no enforcing seccomp allowlist ships in the binary.
9. **Capabilities survive a non-root start.** After `--setup-caps`, a non-root
   sipnab holds `CAP_NET_RAW` and `CAP_NET_ADMIN` from the file itself. The
   privilege drop does nothing for a process that did not start as root
   ([`src/privilege.rs::drop_privileges`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs)),
   and only the scanner-kill worker clears its capability set. On macOS the
   drop also needs an explicit `--user`.
10. **libpcap is C, and it runs briefly as root.** It parses every live
    packet before sipnab's Rust code does, inside the process that holds keys
    and tokens. The capture thread starts reading as soon as it reports the
    device open and does not wait for the privilege drop on the main thread
    ([`src/capture/live.rs::capture_live`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs),
    [`src/app/bootstrap.rs`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs)),
    so the first packets of a root-started run can reach libpcap before the
    drop. The privilege drop and the opt-in sandbox limit the damage after
    that, and nothing removes the risk.
11. **File-tool path check and file open are separate steps.** The MCP file
    tools resolve the path and check it against the root, then open it later.
    A local user who can change links inside `--mcp-file-root` between those
    two steps could redirect a write. Keep the root writable by sipnab alone.
12. **Plugins are not signed.** sipnab loads any module the operator names,
    and a plugin can emit misleading findings even though it cannot touch the
    host.

## Keeping this page true

[`tests/openssf_badge_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/openssf_badge_test.rs) checks that this page names every trust
boundary above, that every path it cites exists, and that every
`file::name` citation names something defined in that file. A renamed
function turns that test red, so the page cannot quietly point at code that
moved.
