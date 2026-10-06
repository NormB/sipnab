# Assurance case

An **assurance case** is an argument, backed by evidence, that a system meets
its security requirements. This page is sipnab's. It answers two questions
that the [threat model](threat-model.md) does not: were well-known secure
design principles applied, and were the most common kinds of implementation
mistake countered? Where the answer is "only partly" or "no", this page says
so, because an operator can add a defense only where they know one is missing.

## How the argument fits together

The case has three layers:

1. **Claim.** sipnab resists the attackers the threat model names, at every
   trust boundary it names, except where a residual risk says otherwise.
2. **Arguments.** Four supports hold up that claim:
   - the [threat model](threat-model.md#assets) names what an attacker wants;
   - the [trust boundaries](threat-model.md#trust-boundaries-at-a-glance) name
     every place attacker-controlled data enters, with the threats and
     mitigations at each;
   - [secure design principles](#secure-design-principles) below shows each
     classic principle applied, or where it is not;
   - [common implementation weaknesses](#common-implementation-weaknesses)
     below walks the 2025 CWE Top 25 and gives each entry a verdict.
3. **Evidence.** Every argument cites the file, and usually the function,
   that implements it, so a reader can check the claim instead of trusting
   it. [Residual risks](threat-model.md#residual-risks-and-known-gaps) lists
   what the evidence does not cover.

## Terms used on this page

- **Secure design principles**: eight rules for building protection
  mechanisms that Jerome Saltzer and Michael Schroeder published in 1975, in
  "The Protection of Information in Computer Systems". The OpenSSF Best
  Practices badge adds two more: a limited attack surface, and input
  validation that uses allowlists.
- **Allowlist**: a list of what a check permits. The check refuses anything
  absent from the list. Its opposite, a denylist, refuses only what it names and
  admits everything else.
- **CWE**: Common Weakness Enumeration, MITRE's catalog of software weakness
  types. Each type has a number, such as CWE-79 for cross-site scripting.
- **CWE Top 25**: MITRE's yearly ranking of the 25 weakness types behind the
  most severe published vulnerabilities. This page uses the
  [2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html),
  published 2025-12-15.
- **`unsafe`**: a Rust keyword that marks code where the compiler cannot prove
  memory safety and the author must. Code outside an `unsafe` block cannot
  write out of bounds, use freed memory or follow a null pointer.
- **Loopback**, **bearer token** and **HMAC**: see the
  [threat model's terms](threat-model.md#terms-used-on-this-page).

## Secure design principles

Each row names a principle, says what it asks for, and says where sipnab
applies it. The last cell is the verdict: **Applied**, or **Partially
applied** with the gap named.

| Principle | What it asks for | How sipnab applies it | Verdict |
|---|---|---|---|
| **Economy of mechanism** | Keep each protection small and simple enough to check. | One token verifier serves both the REST API and MCP ([`src/auth.rs::verify_for`](https://github.com/NormB/sipnab/blob/main/src/auth.rs)). One rate limiter serves REST, MCP and HEP ([`src/rate_limit.rs::FixedWindowLimiter`](https://github.com/NormB/sipnab/blob/main/src/rate_limit.rs)). One path resolver confines `-O`, the MCP file tools and the REST file root ([`src/capture/output_guard.rs::canonical_target`](https://github.com/NormB/sipnab/blob/main/src/capture/output_guard.rs)). A WASM plugin gets no host imports at all, so there is no host interface to review ([`src/plugin/mod.rs::instantiate`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs)). | Partially applied: the "bare file name only" check that runs before that resolver exists twice, once for MCP ([`src/mcp/server.rs::resolve_in_root`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs)) and once for REST ([`src/output/api.rs::resolve_in_file_root`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). The two copies agree today and nothing keeps them agreeing. |
| **Fail-safe defaults** | Deny by default; grant access only by explicit choice. | Every listener (REST, MCP over HTTP, HEP, metrics) is off until a flag turns it on. A listener on a non-loopback address refuses to start without a credential ([`src/output/api.rs::enforce_bind_auth_policy`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs), [`src/capture/hep.rs::enforce_hep_bind_policy`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs)). A REST route that calls the plain guard demands the broadest scope, so a new route admits only full tokens until someone narrows it ([`src/output/api.rs::guard`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). MCP file tools refuse when the operator has set no root ([`src/mcp/server.rs::resolve_in_root`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs)). Scanner-kill, TFPS actions and relay queries are off by default. | Partially applied: a loopback listener with no key configured accepts every local request ([residual risk 2](threat-model.md#residual-risks-and-known-gaps)), and the Landlock sandbox and seccomp filter both default to `off` ([`src/sandbox.rs::SandboxMode`](https://github.com/NormB/sipnab/blob/main/src/sandbox.rs), [`src/seccomp.rs::SeccompMode`](https://github.com/NormB/sipnab/blob/main/src/seccomp.rs)). |
| **Complete mediation** | Check every access, every time, rather than trusting an earlier check. | Every REST handler except `/health` calls a guard that charges the rate limit and then verifies the token's signature, expiry, audience and scope on that request ([`src/output/api.rs::guard_scoped`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs), [`src/output/api.rs::authenticate`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). HTTP MCP applies its check as a layer on the whole router, so no tool route can skip it ([`src/mcp/transport.rs::auth_layer`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs)). A HEP listener checks its source allowlist, rate limit and configured secret or signature on every datagram before using it ([`src/capture/hep.rs::verify_hmac_datagram`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs), [`src/capture/hep.rs::plain_auth_check`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs)). | Partially applied: REST calls the guard inside each handler rather than as one layer, and no test sends an unauthenticated request to every route, so a new handler that forgot the guard would pass the suite. Loopback without a key skips the check entirely (residual risk 2). |
| **Open design** | Security must not depend on the design being secret. | The source is public under MIT or Apache-2.0. Tokens use HMAC-SHA256 from the `hmac` and `sha2` crates, TLS comes from `rustls`, and [Authentication](auth.md) documents the token format. The secrets are the keys, never the method. [`SECURITY.md`](https://github.com/NormB/sipnab/blob/main/SECURITY.md) invites reports. | Applied |
| **Separation of privilege** | Require two independent conditions before a dangerous act. | A TFPS ban needs a token with the `actions` scope *and* a server-side setting that enables actions ([`src/output/api.rs::action_guard`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). Any transmit needs its opt-in flag *and* a live capture source; a capture file can never obtain the permit that creates a send socket ([`src/security/transmit_guard.rs::for_source`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs)). | Applied |
| **Least privilege** | Run each part with the smallest set of rights it needs. | A root start drops to an unprivileged user once the capture device is open, checks that the drop took, and sets `PR_SET_NO_NEW_PRIVS` ([`src/privilege.rs::drop_privileges`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs), [`src/privilege.rs::verify_dropped`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs), [`src/privilege.rs::block_privilege_escalation`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs)). `--chroot` narrows the filesystem ([`src/privilege.rs::do_chroot`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs)). The scanner-kill worker clears its capabilities ([`src/process_isolation/worker_process.rs::clear_capabilities`](https://github.com/NormB/sipnab/blob/main/src/process_isolation/worker_process.rs)). Tokens carry scopes such as `metrics`, `read` and `actions` ([`src/auth.rs::SCOPE_METRICS`](https://github.com/NormB/sipnab/blob/main/src/auth.rs)). | Partially applied: a non-root start after `--setup-caps` keeps `CAP_NET_RAW` and `CAP_NET_ADMIN` for its whole life (residual risk 9), libpcap reads the first packets before the drop (residual risk 10), and the sandbox and seccomp filter are opt-in. |
| **Least common mechanism** | Minimize what different users or parts share, since shared machinery is a path between them. | The scanner-kill sockets live in a separate worker process that starts with an emptied environment ([`src/process_isolation.rs::worker_environment`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs)). API and MCP tokens carry different audiences, so one surface's token fails on the other ([`src/auth.rs::AUDIENCE_MCP`](https://github.com/NormB/sipnab/blob/main/src/auth.rs)). sipnab keeps rate limits per peer, so one noisy client cannot spend the budget of the others. | Partially applied: parsers, keys and tokens otherwise share one process, and exec hook children inherit sipnab's environment (residual risk 6). |
| **Psychological acceptability** | Make the secure way the easy way, or people route around it. | A refusal names the flag that would allow the act, as the MCP file tools and `query_relay` do ([`src/mcp/tools/relay.rs::QueryRelayParams`](https://github.com/NormB/sipnab/blob/main/src/mcp/tools/relay.rs)). Every secret has a file or environment-variable form so it stays out of `ps` output, and `--archive-password` prints a warning naming the safer options ([`src/capture/archive/password.rs::INLINE_WARNING`](https://github.com/NormB/sipnab/blob/main/src/capture/archive/password.rs)). A local run needs no credentials. | Applied |
| **Limited attack surface** | Expose as little as possible to an attacker. | The default build leaves out the REST API, MCP, HEP, WASM plugins and archive input; the `full` feature adds them ([`Cargo.toml`](https://github.com/NormB/sipnab/blob/main/Cargo.toml), `[features]`). A route exists only in builds with its feature ([`src/output/api.rs::build_router`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). In a full build, each listener stays closed until its flag. | Applied |
| **Input validation with allowlists** | Check input against what the program allows, not against a list of known-bad values. | HTTP MCP accepts only `Host` values on an allowlist ([`src/mcp/transport.rs::serve_http`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs)). File tools accept one plain path component and nothing else ([`src/mcp/server.rs::resolve_in_root`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs)). REST bodies that change state reject unknown fields and anything but a JSON object ([`src/output/api.rs::PersistenceRequest`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs), [`src/output/api.rs::set_persistence`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). Options with a fixed set of values parse into enumerations, so an unlisted value is an error. | Partially applied: unknown config keys produce a warning, not an error ([`src/config.rs::unknown_keys`](https://github.com/NormB/sipnab/blob/main/src/config.rs)), and the ban target check is a denylist of loopback, broadcast, multicast and unspecified addresses ([`src/security/actions/mod.rs::check_ban_address`](https://github.com/NormB/sipnab/blob/main/src/security/actions/mod.rs)). |

## Common implementation weaknesses

The table walks the [2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
in rank order. Each verdict is one of:

- **Countered**: a mechanism cited in the row prevents the weakness in
  sipnab's code.
- **Partially countered**: a mechanism exists, and the row names the case it
  does not cover.
- **Not countered**: nothing prevents it.
- **Not applicable**: sipnab has no code of the kind the weakness needs.

### Memory safety: the argument shared by seven rows

CWE-787, 416, 125, 120, 476, 121 and 122 are memory-safety weaknesses. sipnab
uses Rust, and safe Rust checks every slice index, frees memory only
when nothing refers to it, and has no null references. That leaves `unsafe`
blocks and C libraries:

- **`unsafe` blocks** exist only for calls into the operating system and other
  foreign code. [Fault model](fault-model.md) counts them, and
  [`tests/unsafe_census_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/unsafe_census_test.rs) holds that count to the tree.
  Every block must carry a `// SAFETY:` comment that states why it is sound:
  [`Cargo.toml`](https://github.com/NormB/sipnab/blob/main/Cargo.toml) sets clippy's `undocumented_unsafe_blocks` lint,
  and both the pre-push hook ([`.githooks/pre-push`](https://github.com/NormB/sipnab/blob/main/.githooks/pre-push)) and CI
  ([`.github/workflows/ci.yml`](https://github.com/NormB/sipnab/blob/main/.github/workflows/ci.yml)) run clippy with `-D warnings`, so a block
  without one fails the build.
- **The project fuzzes every parser of untrusted bytes**
  ([`fuzz/fuzz_targets/`](https://github.com/NormB/sipnab/tree/main/fuzz/fuzz_targets)), with a smoke tier in ordinary
  CI ([`tests/smoke_fuzz_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/smoke_fuzz_test.rs)).
- **C code remains**: libpcap parses every live packet before sipnab does, and
  the allocator, mimalloc, is C. The Rust argument covers neither
  ([residual risk 10](threat-model.md#residual-risks-and-known-gaps)). That is
  why the buffer rows below say "partially".

### The table

| Rank | CWE | What it is | Verdict | Argument and evidence |
|---|---|---|---|---|
| 1 | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Cross-site scripting: untrusted text reaches a web page as markup. | Countered | No REST route answers with HTML: answers are JSON, plain text (`/health`, `/metrics`) or audio. The one HTML file it writes, the call-flow export, escapes the diagram text before embedding it and has a test that tries to inject a `<script>` tag ([`src/tui/call_flow/export.rs::escape_html`](https://github.com/NormB/sipnab/blob/main/src/tui/call_flow/export.rs)). The website is static and sends a Content Security Policy that allows scripts from its own origin only ([`website/static/_headers`](https://github.com/NormB/sipnab/blob/main/website/static/_headers)). |
| 2 | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | SQL injection. | Not applicable | sipnab has no database and no SQL library in [`Cargo.toml`](https://github.com/NormB/sipnab/blob/main/Cargo.toml). |
| 3 | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Cross-site request forgery: a web page makes the victim's browser send a request the victim did not intend. | Partially countered | Credentials travel in an `Authorization` header, never a cookie, so a browser does not attach them to a forged request. HTTP MCP refuses a `Host` header outside its allowlist, which defeats DNS rebinding ([`src/mcp/transport.rs::serve_http`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs)). **Gap:** the REST API has no `Host` check ([`src/output/api.rs::build_router`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). On a loopback bind with no key, a web page that rebinds its own name to `127.0.0.1` can read the capture through the browser and change the persistence setting. Configure a key, or keep the REST API off, on a machine where someone browses the web. |
| 4 | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | Missing authorization: an action runs without checking that the caller may perform it. | Partially countered | Every REST handler except `/health` calls a guard ([`src/output/api.rs::guard_scoped`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)), and HTTP MCP checks as a layer over all routes ([`src/mcp/transport.rs::auth_layer`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs)). Risky MCP tools also need their own opt-in flag ([`src/mcp/server.rs::open_capture`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs)). **Gap:** no test sweeps every REST route without a token, so the suite would miss a handler added without the guard (see complete mediation above). |
| 5 | [CWE-787](https://cwe.mitre.org/data/definitions/787.html) | Out-of-bounds write. | Partially countered | See [memory safety](#memory-safety-the-argument-shared-by-seven-rows): safe Rust bounds-checks every write, and `unsafe` must state its soundness. libpcap is C. |
| 6 | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Path traversal: a name such as `../../etc/passwd` reaches a file outside the intended directory. | Partially countered | Archive extraction never uses a member's name as a path: it writes to names it generates inside a private directory ([`src/capture/archive/mod.rs::ExtractDir`](https://github.com/NormB/sipnab/blob/main/src/capture/archive/mod.rs)). MCP and REST file access take one plain name, resolve symbolic links and refuse a result outside the configured root ([`src/mcp/server.rs::resolve_in_root`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs), [`src/output/api.rs::resolve_in_file_root`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). **Gap:** the check and the later open are separate steps, so a local user who can swap links inside the root in between could redirect a write ([residual risk 11](threat-model.md#residual-risks-and-known-gaps)). |
| 7 | [CWE-416](https://cwe.mitre.org/data/definitions/416.html) | Use after free. | Partially countered | See [memory safety](#memory-safety-the-argument-shared-by-seven-rows): the borrow checker rejects use after free in safe Rust. libpcap is C. |
| 8 | [CWE-125](https://cwe.mitre.org/data/definitions/125.html) | Out-of-bounds read. | Partially countered | See [memory safety](#memory-safety-the-argument-shared-by-seven-rows). The capture-file reader also checks each record length with checked arithmetic before slicing ([`src/capture/pcap_reader.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/pcap_reader.rs)). libpcap is C. |
| 9 | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | OS command injection: untrusted text becomes part of a shell command. | Partially countered | Exec hooks run the operator's own command through `sh -c`, and captured data reaches it only as `SIPNAB_*` environment variables, never as text spliced into the command ([`src/output/event_exec.rs::spawn_command`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs), [`src/security/alerting.rs`](https://github.com/NormB/sipnab/blob/main/src/security/alerting.rs)). Other child programs get an argument list with no shell ([`src/security/tfps.rs::run_bounded`](https://github.com/NormB/sipnab/blob/main/src/security/tfps.rs), [`src/capture/archive/password.rs::split_command`](https://github.com/NormB/sipnab/blob/main/src/capture/archive/password.rs)). Legacy `%from` placeholders become a quoted `"${SIPNAB_FROM}"` reference that suits the quoting around the placeholder, so the value is one word with no splitting or `*` expansion ([`src/security/exec_placeholders.rs::quote_placeholders`](https://github.com/NormB/sipnab/blob/main/src/security/exec_placeholders.rs)). **Gap:** a hook that uses a variable unquoted, or runs `eval` on one, reintroduces the risk inside the operator's own script (residual risk 6). |
| 10 | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Code injection: untrusted input becomes code the program runs. | Countered | sipnab evaluates no code from its inputs. sipnab parses a filter expression into a tree of comparisons that it evaluates itself, and refuses a malformed one ([`src/sip/dsl.rs::FilterExpr`](https://github.com/NormB/sipnab/blob/main/src/sip/dsl.rs)). The only loaded code is a WASM plugin the operator names, which runs in an interpreter with no host imports and fixed fuel and memory caps ([`src/plugin/mod.rs::instantiate`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs), [`src/plugin/mod.rs::FUEL_PER_DIALOG`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs)). |
| 11 | [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | Classic buffer overflow: a copy with no size check. | Partially countered | See [memory safety](#memory-safety-the-argument-shared-by-seven-rows): a safe Rust copy between slices of different lengths panics instead of overflowing. libpcap is C. |
| 12 | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | Unrestricted upload of a dangerous file type. | Not applicable | Neither the REST API nor MCP accepts a file upload. The only POST bodies are small JSON documents capped at 1 MiB ([`src/output/api.rs::MAX_REQUEST_BODY_BYTES`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). MCP can open a capture already placed in `--mcp-file-root`, behind its own opt-in flag. |
| 13 | [CWE-476](https://cwe.mitre.org/data/definitions/476.html) | Null pointer dereference. | Partially countered | See [memory safety](#memory-safety-the-argument-shared-by-seven-rows): safe Rust has no null references, and a missing value is an `Option` the code must handle. The `unwrap_used` and `expect_used` lints flag the shortcuts that would turn a missing value into a crash ([`src/lib.rs`](https://github.com/NormB/sipnab/blob/main/src/lib.rs)). libpcap is C. |
| 14 | [CWE-121](https://cwe.mitre.org/data/definitions/121.html) | Stack-based buffer overflow. | Partially countered | See [memory safety](#memory-safety-the-argument-shared-by-seven-rows). libpcap is C. |
| 15 | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Deserialization of untrusted data into objects that run code. | Countered | Untrusted JSON and TOML deserialize with `serde` into fixed, typed structures. sipnab uses no format that names its own types, so a document cannot choose what gets built. Bodies that change state reject unknown fields ([`src/output/api.rs::PersistenceRequest`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)), and request bodies are size-capped. |
| 16 | [CWE-122](https://cwe.mitre.org/data/definitions/122.html) | Heap-based buffer overflow. | Partially countered | See [memory safety](#memory-safety-the-argument-shared-by-seven-rows). libpcap and mimalloc are C. |
| 17 | [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | Incorrect authorization: the check exists but grants too much. | Countered | Tokens carry an audience and a scope, and the verifier checks both on every request ([`src/auth.rs::verify_for`](https://github.com/NormB/sipnab/blob/main/src/auth.rs)). A `metrics` token reaches only the metrics route, and a route with no explicit scope demands the broadest ([`src/output/api.rs::guard`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). Actions need the `actions` scope plus a server setting ([`src/output/api.rs::action_guard`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). [`tests/api_token_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/api_token_test.rs) covers scope refusals, and [`tests/mcp_scope_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/mcp_scope_test.rs) the MCP side. |
| 18 | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper input validation. | Partially countered | Parsers of untrusted bytes cap line, buffer and message sizes, and the project fuzzes them ([threat model, packet capture input](threat-model.md#packet-capture-input-live-interfaces)). **Gap:** see the allowlist principle above: unknown config keys warn instead of failing, and the ban target check is a denylist. |
| 19 | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | Improper access control, the parent of the authorization and authentication rows. | Partially countered | The mechanisms in the CWE-862, CWE-863 and CWE-306 rows. **Gap:** sipnab checks the file permissions of archive password files and the HEP TLS key only; it reads signing-key files, `--tls-key` and the config file without checking who else can read or write them ([residual risk 7](threat-model.md#residual-risks-and-known-gaps)). |
| 20 | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Exposure of sensitive information to someone not entitled to it. | Partially countered | sipnab keeps keys out of core dumps and swap, and derived session keys wipe themselves on drop ([`src/privilege.rs::disable_core_dumps`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs), [`src/privilege.rs::lock_key_memory`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs), [`src/rtp/srtp.rs::DerivedSessionKeys`](https://github.com/NormB/sipnab/blob/main/src/rtp/srtp.rs)). The REST API refuses an archive password in a URL ([`src/output/api.rs::refuse_password_in_url_mw`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). **Gap:** HTTP MCP and the metrics endpoint have no TLS, the REST API has TLS only when configured, and authenticated clients see real identities because `--redact` covers vCon export only (residual risks 1 and 3). |
| 21 | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | Missing authentication for a critical function. | Partially countered | A listener on a non-loopback address refuses to start without a credential ([`src/output/api.rs::enforce_bind_auth_policy`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs), [`src/capture/hep.rs::enforce_hep_bind_policy`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs)). **Gap:** on loopback with no key, the REST API and HTTP MCP accept every request, including the persistence switch (residual risk 2). |
| 22 | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Server-side request forgery: a caller makes the server connect to a destination the caller chose. | Countered | sipnab has no HTTP client library. It connects out only to destinations the operator gave on the command line or in the config: the HEP collector (`--hep-send`) and the media relay (`--rtpengine-control`). The relay query tool deliberately takes no address argument ([`src/mcp/tools/relay.rs::QueryRelayParams`](https://github.com/NormB/sipnab/blob/main/src/mcp/tools/relay.rs)), and a run reading a capture file cannot obtain a transmit permit at all ([`src/security/transmit_guard.rs::for_source`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs)). |
| 23 | [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Command injection in general, of which CWE-78 is the shell case. | Partially countered | The CWE-78 row applies unchanged, gap included. The config's `${NAME}` expansion runs once and never recursively ([`src/config.rs::expand_env_vars`](https://github.com/NormB/sipnab/blob/main/src/config.rs)). |
| 24 | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | Authorization bypass through a user-controlled key: changing an id in a request reaches data that belongs to another user. | Partially countered | sipnab has one tenant: every authorized caller may see every call, so a Call-ID in a URL reaches nothing the caller could not list anyway. The one owned resource is a ban, and sipnab refuses to lift a ban it did not place ([`src/security/actions/service.rs`](https://github.com/NormB/sipnab/blob/main/src/security/actions/service.rs), `NotOwned`). **Gap:** ownership is per sipnab instance, not per token, so any `actions` token can lift a ban another token placed. |
| 25 | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Allocation of resources without limits or throttling. | Partially countered | Dialog and stream stores cap and evict ([`tests/resource_bounds_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/resource_bounds_test.rs)). Decompression has a total byte ceiling, a depth cap and a member cap ([`src/capture/pcap_reader.rs::DEFAULT_MAX_GUNZIP_BYTES`](https://github.com/NormB/sipnab/blob/main/src/capture/pcap_reader.rs), [`src/capture/archive/mod.rs::MAX_ENTRIES`](https://github.com/NormB/sipnab/blob/main/src/capture/archive/mod.rs)). REST limits requests per client before authentication, caps bodies and times out slow requests ([`src/output/api.rs::REQUEST_TIMEOUT`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs)). Exec hooks cap live children ([`src/output/event_exec.rs::DEFAULT_QUEUE_DEPTH`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs)). **Gap:** failed HTTP MCP logins have no throttle (residual risk 4), and the per-sender HEP limit is off by default. |

## Findings this review produced

Writing this page against the code turned up gaps the threat model did not
yet list. They stand as open work:

1. **The REST API has no `Host` allowlist.** HTTP MCP has one; REST does not,
   so DNS rebinding reaches a loopback REST API that has no key from a browser
   (CWE-352 row).
2. **No test sweeps every REST route for authentication** (CWE-862 row).
3. **The bare-file-name check exists twice**, once for MCP and once for
   REST (economy of mechanism row).
4. **Ban ownership is per instance, not per token** (CWE-639 row).

## Keeping this page true

[`tests/openssf_badge_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/openssf_badge_test.rs) checks that every principle above has its
own row with a verdict, that every entry of the 2025 CWE Top 25 has exactly
one row with a verdict, and that every path and `file::name` citation names
something that exists. A new edition of the list is a deliberate change to
that test and this page together.
